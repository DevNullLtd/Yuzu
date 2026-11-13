#pragma once

// Metrics of the webhook and offload-target delivery worker pools: the closed `reason` set of the
// two drop counters, and the pending / capacity gauges published on the server's 15 s tick.
//
// One definition of the registration and the publish, so the boot path in `server.cpp` and the
// tests cannot drift apart. The drop counters themselves are incremented by the stores
// (`WebhookStore::fire_event`, `OffloadTargetStore::log_dropped_delivery`), with the reason taken
// from `StoreWorkerPool::drop_reason`.

#include <yuzu/metrics.hpp>

#include <cstddef>

namespace yuzu::server {

inline constexpr char kWebhookDeliveryDroppedMetric[] = "yuzu_server_webhook_delivery_dropped_total";
inline constexpr char kOffloadDeliveryDroppedMetric[] = "yuzu_server_offload_delivery_dropped_total";
inline constexpr char kDeliveryPoolPendingMetric[] = "yuzu_server_delivery_pool_pending";
inline constexpr char kDeliveryPoolCapacityMetric[] = "yuzu_server_delivery_pool_capacity";

/// Describe the drop counters and the two gauges, and pre-seed every series to 0: both `reason`
/// members of both counters, and both `store` members of both gauges. Without the pre-seed a fresh
/// server exposes none of them until the first drop, so `absent()` cannot tell "not wired" from
/// "nothing dropped yet" (docs/observability-conventions.md).
inline void register_delivery_pool_metrics(yuzu::MetricsRegistry& metrics) {
    metrics.describe(kWebhookDeliveryDroppedMetric,
                     "Webhook deliveries dropped at submit, by reason: queue_full (the delivery "
                     "worker pool's queue was full) or quiescing (the store was shutting down)",
                     "counter");
    metrics.describe(kOffloadDeliveryDroppedMetric,
                     "Offload-target deliveries dropped at submit, by reason: queue_full (the "
                     "delivery worker pool's queue was full) or quiescing (the store was shutting "
                     "down)",
                     "counter");
    for (const char* name : {kWebhookDeliveryDroppedMetric, kOffloadDeliveryDroppedMetric})
        for (const char* reason : {"queue_full", "quiescing"})
            metrics.counter(name, {{"reason", reason}});

    // pending counts queued plus running deliveries; capacity is the most pending can be (queue
    // bound plus workers), so pending / capacity near 1 means the next delivery is dropped.
    metrics.describe(kDeliveryPoolPendingMetric,
                     "Deliveries queued or running on a store's delivery worker pool, by store "
                     "(webhook, offload); 0 when the store is not open; published every 15 s",
                     "gauge");
    metrics.describe(kDeliveryPoolCapacityMetric,
                     "Most deliveries a store's delivery worker pool can hold (queue bound plus "
                     "workers), by store (webhook, offload); 0 when the store is not open; "
                     "published every 15 s",
                     "gauge");
    for (const char* store : {"webhook", "offload"}) {
        metrics.gauge(kDeliveryPoolPendingMetric, {{"store", store}}).set(0.0);
        metrics.gauge(kDeliveryPoolCapacityMetric, {{"store", store}}).set(0.0);
    }
}

/// Publish one store's pool depth. A store that is not open reads 0 for both, never a stale value.
inline void publish_delivery_pool(yuzu::MetricsRegistry& metrics, const char* store, bool open,
                                  std::size_t pending, std::size_t capacity) {
    metrics.gauge(kDeliveryPoolPendingMetric, {{"store", store}})
        .set(open ? static_cast<double>(pending) : 0.0);
    metrics.gauge(kDeliveryPoolCapacityMetric, {{"store", store}})
        .set(open ? static_cast<double>(capacity) : 0.0);
}

} // namespace yuzu::server
