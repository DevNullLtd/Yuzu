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
#include "offline_endpoint_types.hpp"
#include "software_catalog_rollup.hpp"
#include "software_catalogue_model.hpp"
#include "software_changes_model.hpp"
#include "software_hosts_model.hpp"
#include "software_inventory_store.hpp"
#include "software_read_api.hpp"

#include <httplib.h>

#include <functional>
#include <string>

namespace yuzu::server {

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
    /// The device table's roster, the fleet snapshot, the clock and the store reads are the
    /// transport-neutral API's own types (software_read_api.hpp), shared with the MCP twins.
    using RosterFn = software_read_api::RosterFn;
    using SnapshotFn = software_read_api::SnapshotFn;
    using NowFn = software_read_api::NowFn;
    /// The store reads, injectable so the route logic is testable without Postgres. Every member a
    /// caller leaves empty is bound to `Deps::store` at registration; with no store the routes
    /// answer 503.
    using Reads = software_read_api::Reads;

    struct Deps {
        FleetReadFn fleet_read_fn;
        AuditFn audit_fn;
        RosterFn roster_fn; ///< empty = no roster wired: names are null and a `q` search is a 503
        SnapshotFn snapshot_fn;
        NowFn now_fn;
        SoftwareInventoryStore* store{nullptr}; ///< borrowed; null (with no `reads`) answers 503
        Reads reads;
    };

    void register_routes(HttpRouteSink& sink, Deps deps);
};

} // namespace yuzu::server
