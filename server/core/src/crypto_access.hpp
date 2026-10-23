#pragma once

/// @file crypto_access.hpp
/// The ONE /crypto availability composition (ADR-0070 R2; fix-spec B1), extracted from
/// `ServerImpl::crypto_access` so it is unit-testable (M4). server.cpp instantiates it with its
/// `AuthRoutes` and hands the result to CryptoRoutes, both forms of GET /api/v1/ca/issued, the
/// Settings CA panel's inventory and the MCP server, so the REST widget list, the dashboard and
/// list_crypto_widgets cannot draw different answers. Drawing only - never a grant: every data
/// route keeps its own gate.
///
/// `Auth` is `AuthRoutes` in production; a test passes a fake with the same two members:
///   bool has_permission(const httplib::Request&, const std::string&, const std::string&);
///   std::expected<A, authz::GateFailure> probe_fleet_read(const httplib::Request&,
///       httplib::Response&, const std::string&, const std::string&);
/// where `A` has `visible_for_query()` returning an optional-like set (present = confined).
/// Both members are NON-AUDITING probes (no denial row: nothing was attempted).

#include "crypto_widget_catalogue.hpp"

#include <httplib.h>

#include <string>

namespace yuzu::server {

/// kGlobal asks `has_permission` and NEVER the fleet-read probe; kFleetRead/kFleetWideOnly ask
/// `probe_fleet_read` and compose through `crypto_widgets::fleet_access` (a 503 from the probe
/// is kDegraded - the check could not be completed - never a refusal or an empty answer).
template <class Auth>
[[nodiscard]] crypto_widgets::Access crypto_access_for(Auth& auth, const httplib::Request& req,
                                                       crypto_widgets::WidgetGate gate,
                                                       const std::string& securable,
                                                       const std::string& operation) {
    namespace cw = crypto_widgets;
    if (gate == cw::WidgetGate::kGlobal)
        return auth.has_permission(req, securable, operation) ? cw::Access::kAvailable
                                                              : cw::Access::kRefused;
    httplib::Response scratch;
    const auto r = auth.probe_fleet_read(req, scratch, securable, operation);
    if (!r)
        return cw::fleet_access(gate, false, false, scratch.status == 503);
    return cw::fleet_access(gate, true, r->visible_for_query().has_value(), false);
}

} // namespace yuzu::server
