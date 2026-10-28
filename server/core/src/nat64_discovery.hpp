#pragma once

/// @file nat64_discovery.hpp
/// ONE process-wide cache of the NAT64 prefixes the network advertises (RFC 7050: the AAAA answer
/// for `ipv4only.arpa` carries the prefix wrapped around 192.0.0.170/171). Shared by every egress
/// check - the OIDC client today, and any later egress check - so
/// a prefix learned by one is known to all and there is no second, differently-behaved copy.
///
/// NEVER SHRINKS. A prefix, once learned, is kept for the life of the process: an answered refresh
/// MERGES into the known set, and an empty, A-only, different or FAILED answer adds nothing and
/// removes nothing, so a resolver an attacker can influence cannot make the server forget a
/// translator it already saw. The TTLs control only WHEN the name is looked up again. A failed
/// lookup is cached for `kNegativeTtl`, so a dead resolver costs one bounded lookup a minute, not
/// one per request.
///
/// The set is bounded (`kMaxPrefixes`). An answer that would take it past the bound is never
/// installed partially: `overflowed` is set and callers must REFUSE the IPv6 destination, because
/// the prefix that was cut off is the one an attacker wants unclassified.
///
/// An INCONCLUSIVE outcome is never remembered, so it cannot persist: the next call looks again (the
/// resolver pool's cap bounds the cost). A resolver that is busy or too slow for every caller's
/// budget therefore stays inconclusive (classified with the prefixes already learned and still
/// refused while the set is in overflow, or refused by a consumer that fails closed) until it recovers, which is the intended behaviour.
///
/// A caller must also treat "no lookup has EVER answered" (`ever_answered == false`) as unknown,
/// not as "no translator": the OIDC path logs and proceeds (its historical behaviour), while a
/// consumer that gates admission may refuse with a retryable error.

#include "oidc_egress_policy.hpp"

#include <spdlog/spdlog.h>

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <chrono>
#include <condition_variable>
#include <functional>
#include <mutex>
#include <vector>

namespace yuzu::server::net {

inline constexpr const char* kNat64ProbeName = "ipv4only.arpa";
inline constexpr std::chrono::minutes kNat64PositiveTtl{10};
inline constexpr std::chrono::minutes kNat64NegativeTtl{1};
inline constexpr std::size_t kMaxDiscoveredNat64Prefixes = 64;

/// The ONE outcome vocabulary every consumer maps its resolver result to (resolver_errors.hpp holds
/// the platform error-code rule):
///   kAnswered      - the resolver answered with at least one AAAA record;
///   kAnsweredNone  - the resolver ANSWERED, and the answer is "no such name / no data" (NXDOMAIN,
///                    NODATA) or only A records: no DNS64 on this network, a normal state;
///   kFailed        - no answer (timeout, SERVFAIL, resolver unavailable): remembered for the
///                    negative TTL;
///   kInconclusive  - THIS call could not get a fair answer (its budget was clamped below a full
///                    lookup, or the resolver pool was busy): treated as failed for this call but
///                    recorded NOWHERE, so one consumer's squeezed budget cannot make another
///                    consumer's next check read "failed".
enum class Nat64LookupOutcome { kAnswered, kAnsweredNone, kFailed, kInconclusive };

/// Monotonic outcome counts, published as metrics from the health tick (no consumer needs a
/// metrics registry).
struct Nat64DiscoveryStats {
    std::atomic<std::uint64_t> answered{0};
    std::atomic<std::uint64_t> answered_none{0};
    std::atomic<std::uint64_t> failed{0};
    std::atomic<std::uint64_t> inconclusive{0};
    std::atomic<std::uint64_t> overflow_refusals{0};
};

struct Nat64DiscoveryCache {
    std::mutex mu;
    std::condition_variable cv; ///< signalled when the single in-flight lookup finishes
    bool inflight{false};       ///< a discovery lookup is running: SINGLE-FLIGHT, at most one process-wide
    bool filled{false};       ///< a lookup has completed (answered or not) since the last reset
    bool ever_answered{false}; ///< a lookup has ANSWERED since the last reset
    bool overflowed{false};
    bool overflow_logged{false}; ///< the overflow transition was reported once (log once, not per call)
    bool last_failed{false};  ///< the most recent lookup did not answer (cached for the negative TTL)
    std::chrono::steady_clock::time_point expires{};
    std::vector<::yuzu::server::oidc::egress::Nat64Prefix> prefixes;
    Nat64DiscoveryStats stats;
    /// Test seam (empty in production): called by the leader right after its lookup returns, before
    /// the answer is parsed, so a test can throw (std::bad_alloc) at the point where allocation
    /// can fail and prove the single flight is released on every exit.
    std::function<void()> test_fault_after_lookup;
};

inline Nat64DiscoveryCache& process_nat64_cache() {
    static Nat64DiscoveryCache c;
    return c;
}

struct Nat64Discovery {
    /// Everything ever learned (the union; never shrinks). Meaningful unless `overflowed`.
    std::vector<::yuzu::server::oidc::egress::Nat64Prefix> prefixes;
    bool overflowed{false};
    bool overflow_started{false}; ///< this call is the one that moved the cache into overflow (log now)
    /// When the lookup failed and was (or already is) cached: how long until the next real lookup,
    /// so a caller's retry hint matches the negative cache. Otherwise the default retry.
    std::chrono::milliseconds retry_after{5000};
    bool looked_up{false};     ///< this call performed a lookup (false: served from the cache)
    bool answered_now{false};  ///< THIS call's lookup answered (false: cached, or the lookup failed)
    bool ever_answered{false}; ///< some lookup, now or earlier, answered
    bool stale{false};         ///< the most recent refresh FAILED: `prefixes` is everything learned earlier
    bool learned_new{false};   ///< this call added at least one prefix
    /// This call could not get a fair answer (busy pool, clamped budget, waiter whose leader gave
    /// none, or an internal error): NOT a resolver failure, recorded nowhere, so a caller must not
    /// log it as "the lookup failed" (a stuck resolver would otherwise warn on every call).
    bool inconclusive{false};
};

/// The lookup callback: fill `out` with the IPv6 answers for `kNat64ProbeName` and return the
/// four-state outcome (answered, answered-none, failed, inconclusive).
using Nat64LookupFn =
    std::function<Nat64LookupOutcome(std::vector<::yuzu::server::oidc::egress::Ipv6>& out)>;

namespace detail {

/// Releases the single flight on EVERY exit from the leader's work (return, exception, bad_alloc):
/// clears `inflight` under the cache mutex and wakes the waiters. Nothing the leader does after
/// taking the flight can leave it set.
struct FlightGuard {
    Nat64DiscoveryCache& cache;
    ~FlightGuard() {
        std::lock_guard lock(cache.mu);
        cache.inflight = false;
        cache.cv.notify_all();
    }
    FlightGuard(const FlightGuard&) = delete;
    FlightGuard& operator=(const FlightGuard&) = delete;
    explicit FlightGuard(Nat64DiscoveryCache& c) : cache(c) {}
};

/// The leader's work: one lookup, then the merge into the cache. Runs under a FlightGuard.
inline Nat64Discovery run_flight(const Nat64LookupFn& lookup, Nat64DiscoveryCache& cache) {
    namespace egress = ::yuzu::server::oidc::egress;
    std::vector<egress::Ipv6> answers;
    Nat64LookupOutcome outcome = Nat64LookupOutcome::kFailed;
    try {
        outcome = lookup(answers);
    } catch (...) {
        outcome = Nat64LookupOutcome::kFailed; // a throwing lookup must not wedge the single flight
        answers.clear();
    }
    if (cache.test_fault_after_lookup)
        cache.test_fault_after_lookup();
    std::vector<egress::Nat64Prefix> found;
    for (const auto& answer : answers)
        if (const auto prefix = egress::discover_prefix_from_ipv4only_answer(answer))
            if (std::find(found.begin(), found.end(), *prefix) == found.end())
                found.push_back(*prefix);
    const bool answered = outcome == Nat64LookupOutcome::kAnswered ||
                          outcome == Nat64LookupOutcome::kAnsweredNone;
    Nat64Discovery d;
    d.looked_up = true;
    d.answered_now = answered;
    std::lock_guard lock(cache.mu);
    switch (outcome) {
    case Nat64LookupOutcome::kAnswered:
        cache.stats.answered.fetch_add(1, std::memory_order_relaxed);
        break;
    case Nat64LookupOutcome::kAnsweredNone:
        cache.stats.answered_none.fetch_add(1, std::memory_order_relaxed);
        break;
    case Nat64LookupOutcome::kFailed:
        cache.stats.failed.fetch_add(1, std::memory_order_relaxed);
        break;
    case Nat64LookupOutcome::kInconclusive:
        cache.stats.inconclusive.fetch_add(1, std::memory_order_relaxed);
        break;
    }
    if (outcome == Nat64LookupOutcome::kInconclusive) {
        // Failed FOR THIS CALL only: nothing is written to the shared state (no negative entry, no
        // TTL change), so the next consumer does a fair lookup of its own.
        d.stale = true;
        d.inconclusive = true;
        d.ever_answered = cache.ever_answered;
        d.overflowed = cache.overflowed;
        if (!cache.overflowed)
            d.prefixes = cache.prefixes;
        return d;
    }
    cache.last_failed = !answered;
    d.stale = !answered;
    if (answered) {
        cache.ever_answered = true;
        std::vector<egress::Nat64Prefix> merged = cache.prefixes;
        for (const auto& prefix : found)
            if (std::find(merged.begin(), merged.end(), prefix) == merged.end())
                merged.push_back(prefix);
        if (merged.size() > kMaxDiscoveredNat64Prefixes) {
            cache.overflowed = true; // keep what was known; never a partial set
            if (!cache.overflow_logged) {
                cache.overflow_logged = true;
                d.overflow_started = true;
                // Reported ONCE per transition, here in the shared cache, so every consumer (and
                // any future one) gets the same single line and none can forget or repeat it.
                spdlog::error("NAT64 discovery: the NAT64 prefix answer for ipv4only.arpa would "
                              "exceed {} learned prefixes; the learned set is frozen in overflow "
                              "and IPv6 destinations are refused (OIDC IdP fetches) until a later "
                              "answer fits or the server is restarted. --oidc-nat64-prefix does NOT "
                              "clear this; a restart does.",
                              kMaxDiscoveredNat64Prefixes);
            }
        } else {
            d.learned_new = merged.size() > cache.prefixes.size();
            cache.prefixes = std::move(merged);
            // An answer that FITS clears an earlier overflow (and re-arms the one-time log). The set
            // never shrinks, though: once a hostile or misconfigured answer has filled it to the
            // bound, every later answer carrying a prefix not already known overflows again - the
            // practical remedy is to restart (see docs/user-manual/server-admin.md).
            cache.overflowed = false;
            cache.overflow_logged = false;
        }
    }
    // A failed lookup changes nothing (an earlier overflow stays in force).
    cache.filled = true;
    cache.expires = std::chrono::steady_clock::now() +
                    (answered && !cache.overflowed && !found.empty() ? kNat64PositiveTtl
                                                                     : kNat64NegativeTtl);
    if (!answered)
        d.retry_after = std::chrono::duration_cast<std::chrono::milliseconds>(kNat64NegativeTtl);
    d.overflowed = cache.overflowed;
    d.ever_answered = cache.ever_answered;
    if (cache.overflowed)
        cache.stats.overflow_refusals.fetch_add(1, std::memory_order_relaxed);
    else
        d.prefixes = cache.prefixes;
    return d;
}

} // namespace detail

/// The learned prefixes, from the cache while it is fresh, else after one `lookup`. The cache mutex
/// is never held across the lookup.
///
/// SINGLE-FLIGHT: at most ONE lookup is ever running process-wide. A caller that finds the cache
/// stale while a lookup is in flight WAITS for it, up to `wait_budget` (its own budget), then reads
/// the freshly filled cache; if the lookup ended without filling it (inconclusive) or is still
/// running when its budget ends, it returns INCONCLUSIVE (failed for this call, counted, recorded
/// nowhere) - it never starts a second lookup on a budget it has already spent. This bounds the resolver slots
/// discovery can ever hold to one: a hung resolver plus a burst of IPv6 sign-ins cannot pin the
/// shared pool and starve unrelated lookups, and an expiry cannot start a stampede.
[[nodiscard]] inline Nat64Discovery discover_nat64_prefixes_cached(
    const Nat64LookupFn& lookup, Nat64DiscoveryCache& cache,
    std::chrono::milliseconds wait_budget = std::chrono::milliseconds{5000}) {
    namespace egress = ::yuzu::server::oidc::egress;
    const auto wait_deadline = std::chrono::steady_clock::now() + wait_budget;
    {
        std::unique_lock lock(cache.mu);
        for (;;) {
        if (cache.filled && std::chrono::steady_clock::now() < cache.expires) {
            Nat64Discovery d;
            d.overflowed = cache.overflowed;
            d.ever_answered = cache.ever_answered;
            d.stale = cache.last_failed;
            if (cache.last_failed)
                d.retry_after = std::max(std::chrono::milliseconds{1000},
                                         std::chrono::duration_cast<std::chrono::milliseconds>(
                                             cache.expires - std::chrono::steady_clock::now()));
            if (cache.overflowed)
                cache.stats.overflow_refusals.fetch_add(1, std::memory_order_relaxed);
            else
                d.prefixes = cache.prefixes;
            return d;
        }
        if (!cache.inflight) {
            cache.inflight = true; // this caller performs the one lookup
            break;
        }
        if (!cache.cv.wait_until(lock, wait_deadline, [&] {
                return !cache.inflight ||
                       (cache.filled && std::chrono::steady_clock::now() < cache.expires);
            }) || !(cache.filled && std::chrono::steady_clock::now() < cache.expires)) {
            // The lookup in flight did not finish within THIS caller's budget, or it ended without
            // filling the cache: inconclusive for this call only, nothing recorded about the
            // resolver.
            cache.stats.inconclusive.fetch_add(1, std::memory_order_relaxed);
            Nat64Discovery d;
            d.stale = true;
            d.inconclusive = true;
            d.ever_answered = cache.ever_answered;
            d.overflowed = cache.overflowed;
            if (!cache.overflowed)
                d.prefixes = cache.prefixes;
            return d;
        }
        }
    }
    detail::FlightGuard flight(cache); // released on every exit below, including an exception
    try {
        return detail::run_flight(lookup, cache);
    } catch (...) {
        // An allocation failure (or anything else) while parsing/merging: this call is
        // inconclusive; the guard clears the flight, so the next caller can look again. It must
        // still carry the cache's CURRENT state: a fresh default would read as "not overflowed,
        // nothing learned" and let the caller skip the overflow refusal and every learned prefix.
        Nat64Discovery d;
        d.looked_up = true;
        d.stale = true;
        d.inconclusive = true;
        try {
            std::lock_guard lock(cache.mu);
            d.ever_answered = cache.ever_answered;
            d.overflowed = cache.overflowed;
            if (!cache.overflowed)
                d.prefixes = cache.prefixes; // may itself throw: handled below
        } catch (...) {
            // Cannot even copy the set: fail CLOSED (refuse), never open.
            d.prefixes.clear();
            d.overflowed = true;
        }
        return d;
    }
}

} // namespace yuzu::server::net
