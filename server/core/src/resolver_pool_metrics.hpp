#pragma once

// Metrics of a bounded name-resolver pool (`ResolverPool`, bounded_resolver.hpp): the in-flight and
// capacity gauges and the per-outcome lookup counter, published from the server's 15 s tick.
//
// One definition of the registration and the publish, parameterised by the metric names, so the
// boot path in `server.cpp`, every pool that reuses it and the tests cannot drift apart.
//
// Why the counter is mirrored and not incremented live: a lookup runs on a request thread inside a
// free function that has no `MetricsRegistry`, and the pool lives for the whole process. The count
// is therefore kept in the pool (`ResolverPool::outcomes`, one increment in `bounded_resolve`) and
// `ResolverPoolPublisher::publish` adds the change since its last call to the registry counter. The
// publisher has no lock: call `publish` from ONE thread (the 15 s tick).

#include "bounded_resolver.hpp"

#include <yuzu/metrics.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>

namespace yuzu::server {

/// One pool's outcome counts, in `net::ResolveStatus` order.
using ResolverOutcomeCounts = std::array<std::uint64_t, net::kResolveStatusCount>;

/// The three metric families of a pool and their HELP text. Instances have static storage; the
/// publisher keeps a pointer to the one it is given.
struct ResolverPoolMetricNames {
    const char* in_flight;
    const char* capacity;
    const char* lookups;
    const char* in_flight_help;
    const char* capacity_help;
    const char* lookups_help;
};

inline constexpr ResolverPoolMetricNames kOidcResolverMetrics{
    "yuzu_server_oidc_resolver_in_flight",
    "yuzu_server_oidc_resolver_pool_capacity",
    "yuzu_server_oidc_resolver_lookups_total",
    "Name lookups outstanding in the resolver pool the OIDC egress path uses, published every 15 "
    "s; a value at the pool's cap means new OIDC lookups fail at once until lookups return; "
    "non-zero only on POSIX builds, so a reading of 0 on another build does not show that no "
    "lookup is outstanding",
    "Slots in the resolver pool the OIDC egress path uses, published every 15 s; the same "
    "value on every build, while the in-flight gauge and the lookups counter are fed only on "
    "POSIX builds",
    "Name lookups made through the OIDC resolver pool, by outcome: ok, not_found (the resolver "
    "answered that the name has no address), temporary (the resolver failed transiently), "
    "timeout (no answer within the bound), busy (the lookup was not started: the pool was "
    "full, a worker could not be started, 8 lookups for the name were already outstanding, or a "
    "lookup for the name was refused or timed out in the last 3 s). Mirrored from the pool every 15 s; non-zero only on POSIX "
    "builds"};

class ResolverPoolPublisher {
public:
    explicit ResolverPoolPublisher(const ResolverPoolMetricNames& names) noexcept
        : names_(&names) {}
    /// The publisher keeps a pointer to the names, so a temporary would leave it dangling.
    explicit ResolverPoolPublisher(const ResolverPoolMetricNames&&) = delete;

    /// Describe the three families and pre-seed every series: both gauges and all five `outcome`
    /// members of the counter at 0, the capacity at `capacity`. Without the pre-seed a fresh server
    /// exposes none of them until the first lookup, so `absent()` cannot tell "not wired" from
    /// "nothing happened yet" (docs/observability-conventions.md). `baseline` is the pool's counts
    /// now: the pool is process-wide, so a second server in one process must not inherit its
    /// history as its own.
    void register_metrics(yuzu::MetricsRegistry& metrics, int capacity,
                          const ResolverOutcomeCounts& baseline) {
        metrics.describe(names_->in_flight, names_->in_flight_help, "gauge");
        metrics.describe(names_->capacity, names_->capacity_help, "gauge");
        metrics.describe(names_->lookups, names_->lookups_help, "counter");
        metrics.gauge(names_->in_flight).set(0.0);
        metrics.gauge(names_->capacity).set(static_cast<double>(capacity));
        for (std::size_t i = 0; i < net::kResolveStatusCount; ++i)
            metrics.counter(names_->lookups,
                            {{"outcome", net::resolve_status_label(
                                             static_cast<net::ResolveStatus>(i))}});
        last_ = baseline;
    }

    /// Set both gauges and add the change in each outcome count since the last call to its counter.
    /// A count below the last one (the pool was replaced) adds nothing and becomes the new base.
    void publish(yuzu::MetricsRegistry& metrics, int in_flight, int capacity,
                 const ResolverOutcomeCounts& counts) {
        metrics.gauge(names_->in_flight).set(static_cast<double>(in_flight));
        metrics.gauge(names_->capacity).set(static_cast<double>(capacity));
        for (std::size_t i = 0; i < net::kResolveStatusCount; ++i) {
            if (counts[i] > last_[i])
                metrics
                    .counter(names_->lookups,
                             {{"outcome", net::resolve_status_label(
                                              static_cast<net::ResolveStatus>(i))}})
                    .increment(static_cast<double>(counts[i] - last_[i]));
            last_[i] = counts[i];
        }
    }

private:
    const ResolverPoolMetricNames* names_;
    ResolverOutcomeCounts last_{};
};

} // namespace yuzu::server
