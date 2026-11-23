#pragma once

/// @file live_gauge_mirror.hpp
/// Header-only RAII mirror of the held per-device live reads (the `SseSurface::kLiveRead`
/// leases of the shared held-open budget) into the `yuzu_server_live_inflight` gauge.
///
/// Both surfaces that take a `kLiveRead` lease use it (the REST live route and the quarantine
/// release wait, and the MCP `get_device_live` tool), so the one gauge reports the lease count
/// of the one budget whichever surface holds it.
///
/// Usage contract: declare the mirror BEFORE the lease it reports on. Locals are destroyed in
/// reverse order, so the lease is returned first and the destructor then publishes the count
/// WITHOUT it. Call `publish()` once after an acquire. Both the gauge and the budget are borrowed
/// and may be null (the unmetered test seam); neither is owned and neither may be freed while the
/// mirror lives. Publishing never throws: observability must not fail a request.

#include "stream_budget.hpp"

#include <yuzu/metrics.hpp>

#include <cstddef>

namespace yuzu::server::detail {

class LiveGaugeMirror {
public:
    LiveGaugeMirror(StreamBudget* budget, yuzu::Gauge* gauge) noexcept
        : budget_(budget), gauge_(gauge) {}
    ~LiveGaugeMirror() { publish(); }
    LiveGaugeMirror(const LiveGaugeMirror&) = delete;
    LiveGaugeMirror& operator=(const LiveGaugeMirror&) = delete;

    void publish() noexcept {
        if (budget_ == nullptr || gauge_ == nullptr)
            return;
        try {
            gauge_->set(static_cast<double>(budget_->active_for_surface(SseSurface::kLiveRead)));
        } catch (...) { // NOLINT(bugprone-empty-catch) observability must not fail a request
        }
    }

private:
    StreamBudget* budget_;
    yuzu::Gauge* gauge_;
};

} // namespace yuzu::server::detail
