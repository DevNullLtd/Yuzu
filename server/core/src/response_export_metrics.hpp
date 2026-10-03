#pragma once

/// @file response_export_metrics.hpp
/// Observability for the response routes' strict numeric parsing and bounded exports
/// (#4644 / #4703): two closed-label counter families, their startup seed, and the
/// emit helpers shared by the legacy REST, REST v1 and MCP surfaces. Kept apart from
/// `response_query_params.hpp` so that header stays pure (no logging, no registry).

#include <atomic>
#include <chrono>
#include <cstdint>
#include <string>
#include <string_view>

#include <spdlog/spdlog.h>
#include <yuzu/metrics.hpp>

#include "response_query_params.hpp"

namespace yuzu::server {

/// `yuzu_server_response_param_rejected_total{surface}`: a response query numeric
/// parameter was refused as malformed (400 on REST, -32602 on MCP). Operational, not
/// `event="security"`: a rejected `?limit=100abc` is a client bug, not an attack signal.
inline constexpr const char* kResponseParamRejectedMetric =
    "yuzu_server_response_param_rejected_total";
/// `yuzu_server_response_export_truncated_total{surface,cause}`: a response export was
/// cut (rows left out) by the row cap or the payload byte cap. `cause=byte_cap` wins
/// when both fired (`ExportCut::cause()`).
inline constexpr const char* kResponseExportTruncatedMetric =
    "yuzu_server_response_export_truncated_total";

/// The closed label values: the legacy REST route, the REST v1 routes, MCP.
inline constexpr const char* kResponseParamSurfaces[] = {"rest", "rest_v1", "mcp"};
inline constexpr const char* kResponseExportSurfaces[] = {"rest", "rest_v1"};
inline constexpr const char* kResponseExportCauses[] = {"row_cap", "byte_cap"};

/// Describe and pre-seed every series of both families so an idle server exports zeros
/// (`absent()` alerting stays distinguishable from a scrape failure). Called once at
/// startup from `ServerImpl`; the label sets live here so an emit site cannot add a
/// value the seed lacks.
inline void seed_response_metrics(yuzu::MetricsRegistry& m) {
    m.describe(kResponseParamRejectedMetric,
               "Response query numeric parameters refused as malformed (400 on REST, -32602 "
               "on MCP), by surface (rest/rest_v1/mcp) - a client bug signal, not an attack "
               "signal",
               "counter");
    m.describe(kResponseExportTruncatedMetric,
               "Response exports cut so rows were left out, by surface (rest/rest_v1) and "
               "cause (row_cap = more matching rows than the limit; byte_cap = the 50 MiB "
               "payload cap, preferred when both fired) - the export carries "
               "X-Result-Truncated-By-Cap / result_truncated_by_cap and a -truncated "
               "filename; a sustained rate means exports are being consumed incomplete",
               "counter");
    for (const auto* surface : kResponseParamSurfaces)
        m.counter(kResponseParamRejectedMetric, {{"surface", surface}});
    for (const auto* surface : kResponseExportSurfaces)
        for (const auto* cause : kResponseExportCauses)
            m.counter(kResponseExportTruncatedMetric, {{"surface", surface}, {"cause", cause}});
}

/// Count one rejected numeric parameter. A null registry and any exception are
/// swallowed: observability must never fail the request it describes.
inline void count_response_param_rejected(yuzu::MetricsRegistry* m, const char* surface) noexcept {
    if (m == nullptr)
        return;
    try {
        m->counter(kResponseParamRejectedMetric, {{"surface", surface}}).increment();
    } catch (...) { // NOLINT(bugprone-empty-catch)
    }
}

/// Count one cut export and, for a BYTE-cap cut only, warn at most once a minute per
/// process (a looping consumer must not flood the log). `cid` is the request's
/// correlation id, or empty on the legacy surface, which has none. Never logs
/// instruction or agent ids: they are unbounded and are never metric labels either.
inline void record_response_export_cut(yuzu::MetricsRegistry* m, const char* surface,
                                       const ExportCut& cut, std::string_view cid) noexcept {
    if (!cut.any())
        return;
    try {
        if (m != nullptr)
            m->counter(kResponseExportTruncatedMetric,
                       {{"surface", surface}, {"cause", cut.cause()}})
                .increment();
        if (cut.byte_cap) {
            using clock = std::chrono::steady_clock;
            static std::atomic<clock::rep> last_warn{0};
            const auto now = clock::now().time_since_epoch().count();
            auto prev = last_warn.load(std::memory_order_relaxed);
            const auto window =
                std::chrono::duration_cast<clock::duration>(std::chrono::seconds(60)).count();
            // prev == 0 means "never warned"; steady_clock counts from boot, so a real
            // reading is never 0 in practice.
            if ((prev == 0 || now - prev >= window) &&
                last_warn.compare_exchange_strong(prev, now, std::memory_order_relaxed))
                spdlog::warn("response export cut by the payload byte cap (surface={}, "
                             "correlation_id={}); rate-limited to one warning per minute",
                             surface, cid.empty() ? std::string("n/a") : std::string(cid));
        }
    } catch (...) { // NOLINT(bugprone-empty-catch)
    }
}

} // namespace yuzu::server
