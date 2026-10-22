#pragma once

/// @file crypto_routes.hpp
/// `/crypto` - the crypto-library-presence surface (slice 1): the page shell, the two HTMX
/// fragments and the two read-only REST v1 routes. One route owner, modelled on
/// `ComplianceRoutes`; zero routes live inline in server.cpp. The data is read through the
/// store-free `CryptoApi` seam (crypto_api.hpp) - the SAME instance the MCP twins
/// `get_crypto_libraries` / `list_crypto_library_devices` call, so the three surfaces cannot
/// disagree - and shaped by the one pure model (crypto_library_model.hpp).
///
/// Presence and versions only (ADR-1005 D2): nothing here labels a library or version good,
/// bad, current or out of date.
///
/// AUTH: the `/crypto` page shell is auth-only chrome. EVERY data route (both fragments and
/// both REST routes) gates SOLELY on `FleetReadFn` (`Inventory:Read`, ADR-0017
/// admit-then-filter) - never stacked on a bare permission check - and pushes the gate's
/// scope into the read. An unwired gate fails closed (503). Gate refusals are audited by the
/// gate itself; this file audits only the reads it serves (`crypto.libraries.view`,
/// `crypto.libraries.devices`), set-and-proceed: a row that does not persist sets
/// `Sec-Audit-Failed: true` on every route, `audit_persisted: false` in the REST body, and a
/// visible notice on the fragment (crypto_html::kAuditNotPersistedNotice). The detail carries
/// `scope=fleet|confined` (ADR-0017 INV-9). Every data route answers `Cache-Control: no-store,
/// private` and `Vary: Authorization, Cookie, X-Yuzu-Token` (per-caller, scope-filtered data).
///
/// Fragments answer HTTP 200 with a caveat box for a refusal, a bad parameter or a store
/// degrade (htmx does not swap a 4xx); REST returns the real codes.
///
/// DASHBOARD WIDGETS (ADR-0070 D13, R2). `GET /api/v1/crypto/widgets` serves the pure
/// catalogue (crypto_widget_catalogue.hpp) with each widget's availability for the caller,
/// decided by the ONE non-auditing `access_fn` (drawing, not acting) that server.cpp also hands
/// the MCP server. `GET`/`PUT /api/v1/crypto/dashboard/layout` read and replace the caller's OWN
/// layout, keyed by the session username and never another operator's: a service-scoped token
/// is refused (403, no `.permission` - no grant would admit it) and an MCP-tiered token passes
/// the tier belt (`tier_policy_fn`, Infrastructure Read/Write), as the result-set routes do. The
/// PUT is same-site gated (`WriteGate`), versioned (`expected_version`; a stale one is 409) and
/// "no audit row, no mutation" (`detail::audit_attempted`, then the outcome row
/// `crypto.dashboard.layout.update`; an unknown commit outcome is 503 + `outcome=unknown`).
/// `GET /api/v1/crypto/ca/stats` serves the Yuzu-issued COUNTS (ADR-0070 D6: Yuzu's own CA,
/// never the fleet's) behind `fleet_read_fn` Inventory:Read and WITHHELD from a confined caller
/// (403, R2 - never a narrowed count), audited `crypto.ca.stats.view` set-and-proceed. The
/// certificate ROWS behind a count are the filtered `GET /api/v1/ca/issued` (ca_routes, Security
/// :Read) - this file only serves their dashboard fragment.
///
/// The `/crypto` page body is the widget dashboard: `/fragments/crypto/dashboard` draws the
/// caller's layout and EVERY card inline from at most one library summary and one Yuzu-issued
/// stats read, each behind its own gate and audited ONCE per render (`widgets=<n>` in the
/// detail). `/fragments/crypto/widget/{id}` redraws one card (Retry, a card just added) and is
/// audited per request. The drill `/fragments/crypto/ca/certificates` is `perm_fn` Security:Read
/// and withheld from a confined caller, audited `crypto.ca.certificates.view`. All three answer
/// 200 with a note or a banner on refusal or degrade, like the library fragments.

#include <yuzu/server/auth.hpp>

#include "audited_write.hpp" // WriteGate (same-site gate for the layout PUT)
#include "authz_gates.hpp" // authz::FleetReadGate
#include "crypto_api.hpp"
#include "crypto_widget_catalogue.hpp" // Access / WidgetGate (pure)
#include "http_route_sink.hpp"

#include <httplib.h>

#include <functional>
#include <memory>
#include <optional>
#include <string>

namespace yuzu::server {

class CryptoRoutes {
public:
    using AuthFn =
        std::function<std::optional<auth::Session>(const httplib::Request&, httplib::Response&)>;
    using AuditFn = std::function<bool(const httplib::Request&, const std::string& action,
                                       const std::string& result, const std::string& target_type,
                                       const std::string& target_id, const std::string& detail)>;
    using FleetReadFn =
        std::function<authz::FleetReadGate(const httplib::Request&, httplib::Response&,
                                           const std::string& securable_type,
                                           const std::string& operation)>;
    using CryptoApiPtr = std::shared_ptr<const CryptoApi>;
    /// The auditing permission gate (`require_permission`): writes 401/403/503 and returns false.
    using PermFn = std::function<bool(const httplib::Request&, httplib::Response&,
                                      const std::string& securable_type,
                                      const std::string& operation)>;
    /// The ONE non-auditing availability callback (server.cpp builds it once over
    /// `AuthRoutes::probe_fleet_read` and `has_permission`, and hands the same function to the
    /// MCP server): decides what to DRAW only, never a gate.
    using AccessFn = std::function<crypto_widgets::Access(
        const httplib::Request&, crypto_widgets::WidgetGate, const std::string& securable_type,
        const std::string& operation)>;

    /// `TierPolicyFn`'s shape (auth_routes.hpp), restated so this presentation TU never includes
    /// the store-bearing auth_routes.hpp (seam lint).
    using TierFn = std::function<bool(const httplib::Request&, httplib::Response&,
                                      const auth::Session&, const std::string& securable_type,
                                      const std::string& operation)>;

    struct Deps {
        AuthFn auth_fn;
        /// The SOLE gate on every library data route and on the Yuzu-issued counts
        /// (Inventory:Read). Empty = misconfigured -> 503 (fail closed).
        FleetReadFn fleet_read_fn;
        /// Nullable: a null seam answers 503 / the degrade banner, never an empty result.
        CryptoApiPtr api;
        AuditFn audit_fn;
        /// The Yuzu-issued drill's gate (`Security:Read`, the gate of GET /api/v1/ca/issued).
        /// Empty = misconfigured -> 503 (fail closed).
        PermFn perm_fn;
        /// Availability for /api/v1/crypto/widgets and the dashboard. Empty -> 503.
        AccessFn access_fn;
        /// Same-site gate of the layout PUT (cookie callers must name this site).
        WriteGate write_gate;
        /// The MCP tier belt on the layout routes (`AuthRoutes::gateless_tier_policy_fn`). Empty:
        /// pass-through for an untiered session, 503 for a tiered one (fail closed).
        TierFn tier_policy_fn;
    };

    /// Production overload - wraps `httplib::Server&` in an HttplibRouteSink.
    void register_routes(httplib::Server& svr, Deps deps);

    /// Sink-based overload - used by tests (tests/unit/server/test_route_sink.hpp).
    void register_routes(HttpRouteSink& sink, Deps deps);

private:
    Deps deps_;
};

} // namespace yuzu::server
