#pragma once

/// @file software_export_routes.hpp
/// REST route for the streamed installed-software export (SAM-36, roadmap 3.3):
///
///   GET /api/v1/inventory/software/export?format=jsonl|csv[&<list filters>]
///
/// Authorization is `fleet_read_fn(req, res, "Inventory", "Read")` and nothing else (ADR-0017
/// admit-then-filter; never stacked with a permission gate, which would make the confined branch
/// unreachable). The gate's scope is the only filter. Every page comes from the list model's
/// scoped page reader, so a confined caller's stream holds only rows in its scope.
///
/// The scope boundary, stated exactly: a scope of at most software_catalogue::kScopePushdownMaxIds
/// devices is pushed into the store query. A wider scope is read by the server and filtered in
/// process, so out-of-scope rows ARE read from the store but no byte of one reaches the response.
/// Under that wider scope a read can hold none of the caller's rows; the stream resumes from the
/// last row the server scanned, held in process (software_catalogue::read_scoped_step, skip 0, so
/// no store read uses an OFFSET and a run of any length is walked) and ends only when the walk
/// reports the end of the data. That position names a row the caller may not see: it never reaches
/// a response byte, header, log line, metric label or audit detail, and no cursor is decoded on
/// this route.
///
/// Sequence: gate -> parse (400) -> lease (refused: 503 + a `denied` audit row, nothing streamed)
/// -> audit (BEFORE the provider; set-and-proceed with `Sec-Audit-Failed: true` on a miss) ->
/// headers -> chunked provider. The provider reads one page per call and holds no store lease
/// between calls. A degraded read, the wall-clock deadline, a size limit
/// (--inventory-export-max-rows / -bytes) or a server shutdown makes it return
/// false, which aborts the chunked response WITHOUT its terminating chunk, so every HTTP client
/// sees a truncated transfer: after the headers are sent that is the only failure signal there is.
/// There is no trailer record; the size limits are Deps::limits. No second audit row is written
/// at stream end.
///
/// ADMISSION (ADR-0034): the stream pins an HTTP worker for up to 900 s, so it is one lease from the
/// server's ONE StreamBudget (`SseSurface::kSoftwareExport`), like every other held-open response.
/// The export cap `--inventory-export-concurrency` is that lease's per-key cap, counted under the
/// single surface-wide key `detail::kSoftwareExportSurfaceKey`: server-wide, no per-principal share.
/// The lease is released FIRST in the response's resource-releaser (a clean end, an abort, a
/// dropped client, the deadline or a shutdown all run it), and an engine principal's pending quota
/// slot is adopted into the same releaser (UP-1), so neither outlives the stream or dies early.
/// Either limit refusing is one 503 with a retry hint; the audit text and the rejected counter's
/// `reason` say which one. A null budget is a logged fail-closed 503 after the gate, never an
/// unmetered export.
///
/// Registered from server.cpp ahead of `RestApiV1::register_routes`, because the generic
/// `GET /api/v1/inventory/{a}/{b}` would otherwise take the path (same reason as
/// software_read_routes.hpp).

#include "authz_gates.hpp"
#include "http_route_sink.hpp"
#include "offline_endpoint_types.hpp"
#include "software_catalogue_model.hpp"
#include "software_export_stream.hpp"
#include "software_inventory_store.hpp"
#include "stream_budget.hpp"

#include <httplib.h>

#include <yuzu/metrics.hpp>

#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace yuzu::server {

class SoftwareExportRoutes {
public:
    /// The fleet-read gate: `admitted == false` means the response (401/403/503) is already written.
    using FleetReadFn =
        std::function<authz::FleetReadGate(const httplib::Request&, httplib::Response&,
                                           const std::string& securable_type,
                                           const std::string& operation)>;
    using AuditFn = std::function<bool(const httplib::Request& req, const std::string& action,
                                       const std::string& result, const std::string& target_type,
                                       const std::string& target_id, const std::string& detail)>;
    /// The device roster, read once per stream for the hostnames. Display-only: a failed or
    /// unwired read leaves the names null.
    using RosterFn = std::function<std::optional<OfflineRoster>()>;
    /// Monotonic seconds for the stream deadline; empty = std::chrono::steady_clock.
    using SecondsFn = std::function<std::int64_t()>;

    /// The store reads, injectable so the route logic is testable without Postgres. Every member a
    /// caller leaves empty is bound to `Deps::store` at registration; with no store the route
    /// answers 503.
    struct Reads {
        software_catalogue::DevicesReader installs;
        std::function<std::optional<std::unordered_map<std::string, std::int64_t>>(
            const std::vector<std::string>&)>
            last_seen;
        /// The distinct versions of a title within the caller's scope, for a version range.
        std::function<std::optional<std::vector<std::string>>(
            const std::string&, const std::optional<std::vector<std::string>>&)>
            distinct_versions;
    };

    struct Deps {
        FleetReadFn fleet_read_fn;
        AuditFn audit_fn;
        RosterFn roster_fn;
        SecondsFn seconds_fn;
        SoftwareInventoryStore* store{nullptr}; ///< borrowed; null (with no `reads`) answers 503
        Reads reads;
        yuzu::MetricsRegistry* metrics{nullptr};
        /// THE held-open budget (ADR-0034), borrowed. Null answers 503 after the gate: production
        /// always wires the one instance, and an export is never served unmetered.
        detail::StreamBudget* stream_budget{nullptr};
        int concurrency{software_export::kDefaultConcurrency}; ///< --inventory-export-concurrency
        /// --inventory-export-max-rows / --inventory-export-max-bytes (clamped at registration).
        software_export::Limits limits{};
    };

    void register_routes(HttpRouteSink& sink, Deps deps);
};

} // namespace yuzu::server
