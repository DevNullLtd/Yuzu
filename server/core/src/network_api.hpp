#pragma once

/// @file network_api.hpp
/// The FIRST per-family in-process API seam for the presentation/core/engine
/// split (ADR-0031, WS-A4/WS-A2r pilot). Abstract, ZERO store-shaped
/// dependencies — only the pure `network_perf_model.hpp` types + std headers,
/// so this header can be included by a future presentation-side client
/// without dragging the server's store/registry/pg:: layer along.
///
/// The method set == the public REST resources it stands in front of
/// (`GET /api/v1/network/fleet`, `GET /api/v1/network/devices`) so a
/// presentation/MCP caller consumes only what the public, versioned core API
/// serves (ADR-0031 B3, INV-31-4 "no private core API") — a local in-process
/// implementation today (`LocalNetworkApi`, network_api.cpp), a core HTTP
/// client after the WS-B2 cutover. Adding a method here without a
/// corresponding public REST/MCP resource would reintroduce a private core
/// API and defeat the point of the seam.
///
/// The store-backed factory (`make_local_network_api`) lives in the core-only
/// `network_api_local.hpp` — this header names no store type at all, not even
/// by forward declaration, so a presentation TU including it cannot reach one.

#include <optional>
#include <string>
#include <vector>

#include "network_perf_model.hpp"

namespace yuzu::server {

/// Parameters for the ONE device list — mirrors GET /api/v1/network/devices'
/// query params (metric, filter=not_reporting, cooc, key, cohort_value,
/// limit) 1:1, so a REST/MCP/dashboard caller can build one of these directly
/// from its own parsed request with no reshaping.
struct NetDeviceQuery {
    NetPerfMetric metric{NetPerfMetric::kRtt};
    bool not_reporting{false};
    NetCoocFilter cooc{NetCoocFilter::kNone};
    std::string cohort_key;                       ///< "" == no cohort resolution
    std::optional<std::string> cohort_filter;      ///< nullopt == no cohort_value filter
    int limit{50};
};

/// The in-process public network API. Method set == the public REST resources
/// (/api/v1/network/fleet, /api/v1/network/devices) so presentation/MCP
/// consume only what the public, versioned core API serves (ADR-0031 B3,
/// INV-31-4) — a local in-process client today, a core HTTP client after the
/// WS-B2 cutover.
class NetworkApi {
public:
    virtual ~NetworkApi() = default;

    /// Fleet-now rollup for one cohort key ("" == no cohort resolution) —
    /// the shape GET /api/v1/network/fleet serves, plus `available_keys`
    /// (ADR-0031 WS-A4 parity addition, see network_perf_model.hpp) so a
    /// caller with no access to the raw snapshot can still populate a
    /// cohort-key picker. `available_keys` is the distinct-tag-KEY namespace
    /// and is resolved UNCONDITIONALLY — even for cohort_key=="" (the key-less
    /// fleet surface) — because it does not depend on the cohort key; the impl's
    /// 5s memo bounds the extra tag read. (This deliberately differs from DEX,
    /// which withholds available_keys from its pollable fleet endpoint; network
    /// has no /cohorts route, so /api/v1/network/fleet carries it.)
    [[nodiscard]] virtual NetPerfFleetNow fleet_now(const std::string& cohort_key) const = 0;

    /// The ONE device list behind every /network drill — the shape
    /// GET /api/v1/network/devices serves.
    [[nodiscard]] virtual std::vector<NetPerfDeviceRow>
    device_list(const NetDeviceQuery& q) const = 0;
};

} // namespace yuzu::server
