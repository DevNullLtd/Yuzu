#pragma once

/// @file software_read_routes.hpp
/// REST routes for the installed-software v3 reads (SAM-33, roadmap 3.7b):
///
///   GET /api/v1/inventory/software/hosts                one row per reporting device + facet state
///   GET /api/v1/inventory/software/hosts/{agent_id}     one device plus its installs page
///   GET /api/v1/inventory/software/changes              the install/remove/upgrade change feed
///   GET /api/v1/inventory/software/summary              headline device and change counts
///   GET /api/v1/inventory/software/plugin-health        per-facet collection health
///
/// Authorization is `fleet_read_fn(req, res, "Inventory", "Read")` and nothing else (ADR-0017
/// admit-then-filter): stacking a permission gate on it would make the confined branch
/// unreachable (the falsifier is the comment above GET /api/v1/inventory/software in
/// rest_api_v1.cpp). The gate's scope is the only filter. Every page is confined by
/// software_catalogue::read_scoped_page, so a cursor never names an out-of-scope row.
///
/// The two aggregates (summary, plugin-health) are fleet-wide figures and are served from an
/// in-memory snapshot the catalogue rollup thread refreshes, to a globally admitted caller ONLY.
/// A confined caller gets a LIVE aggregate with its scope pushed into SQL (up to
/// kScopePushdownMaxIds devices) or nulls with `omitted = "scope"`; the snapshot is never
/// filtered for a caller, because a filtered fleet rollup cannot be made exact.
///
/// A host that is outside the caller's scope and a host that has no report answer the same 404, and
/// the out-of-scope arm does no read, so neither the body nor a timing or 503 difference is an
/// existence oracle.
///
/// Registered from server.cpp ahead of `RestApiV1::register_routes`, because the generic
/// `GET /api/v1/inventory/{a}/{b}` would otherwise take the two-segment paths (hosts, changes,
/// summary, plugin-health).

#include "authz_gates.hpp"
#include "http_route_sink.hpp"
#include "software_catalogue_model.hpp"
#include "software_changes_model.hpp"
#include "software_hosts_model.hpp"
#include "software_inventory_store.hpp"

#include <httplib.h>

#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace yuzu::server {

/// The fleet-wide aggregates the rollup thread computes once per tick, immutable once published.
struct SoftwareFleetSnapshot {
    std::vector<FacetHealth> facets;
    SoftwareSummary summary;
    std::int64_t as_of{0}; ///< epoch seconds the snapshot was computed
};

/// Single-writer (the rollup thread) / many-reader holder. A failed refresh simply does not call
/// publish(), so the last good snapshot stays.
class SoftwareFleetSnapshotHolder {
public:
    [[nodiscard]] std::shared_ptr<const SoftwareFleetSnapshot> get() const {
        std::lock_guard lock(mu_);
        return snapshot_;
    }
    void publish(std::shared_ptr<const SoftwareFleetSnapshot> s) {
        std::lock_guard lock(mu_);
        snapshot_ = std::move(s);
    }

private:
    mutable std::mutex mu_;
    std::shared_ptr<const SoftwareFleetSnapshot> snapshot_;
};

class SoftwareReadRoutes {
public:
    /// The fleet-read gate (same type as InventoryRoutes::FleetReadFn): `admitted == false` means
    /// the response (401/403/503) is already written.
    using FleetReadFn =
        std::function<authz::FleetReadGate(const httplib::Request&, httplib::Response&,
                                           const std::string& securable_type,
                                           const std::string& operation)>;
    using AuditFn = std::function<bool(const httplib::Request& req, const std::string& action,
                                       const std::string& result, const std::string& target_type,
                                       const std::string& target_id, const std::string& detail)>;
    /// agent_id -> hostname: the device table's roster (the one the UI device table reads).
    using HostnamesFn = std::function<std::unordered_map<std::string, std::string>()>;
    /// The current fleet snapshot, or null before the first successful refresh.
    using SnapshotFn = std::function<std::shared_ptr<const SoftwareFleetSnapshot>()>;
    using NowFn = std::function<std::int64_t()>; ///< epoch seconds; empty = the system clock

    /// The store reads, injectable so the route logic is testable without Postgres. Every member a
    /// caller leaves empty is bound to `Deps::store` at registration; with no store the routes
    /// answer 503.
    struct Reads {
        software_hosts::HostsReader hosts;
        software_changes::ChangesReader changes;
        software_catalogue::DevicesReader installs;
        std::function<std::optional<std::unordered_map<std::string, std::int64_t>>(
            const std::vector<std::string>&)>
            last_seen;
        std::function<std::optional<std::vector<FacetHealth>>(
            const std::optional<std::vector<std::string>>&)>
            facet_health;
        std::function<std::optional<SoftwareSummary>(
            std::int64_t, const std::optional<std::vector<std::string>>&)>
            summary;
        std::function<std::optional<CatalogRollupMeta>()> catalog_meta;
    };

    struct Deps {
        FleetReadFn fleet_read_fn;
        AuditFn audit_fn;
        HostnamesFn hostnames_fn;
        SnapshotFn snapshot_fn;
        NowFn now_fn;
        SoftwareInventoryStore* store{nullptr}; ///< borrowed; null (with no `reads`) answers 503
        Reads reads;
    };

    void register_routes(HttpRouteSink& sink, Deps deps);
};

} // namespace yuzu::server
