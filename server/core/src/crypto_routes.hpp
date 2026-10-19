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
/// DASHBOARD WIDGETS (ADR-0070 D13). `GET /api/v1/crypto/widgets` serves the pure catalogue
/// (crypto_widget_catalogue.hpp) with each widget's `available` flag for the caller, decided by
/// the NON-auditing `has_perm_fn` (drawing, not acting). `GET`/`PUT
/// /api/v1/crypto/dashboard/layout` read and replace the caller's OWN layout, keyed by the
/// session username and never another operator's: authentication only (the layout chooses
/// what is drawn; every widget's data read keeps its own gate). The PUT is same-site gated
/// (`WriteGate`) and "no audit row, no mutation" (`detail::audit_attempted`, then the outcome
/// row `crypto.dashboard.layout.update`). `GET /api/v1/crypto/ca/stats` and
/// `GET /api/v1/crypto/ca/certificates` serve Yuzu's OWN issued certificates (ADR-0070 D6:
/// never the fleet's) behind `perm_fn` `Security:Read`, audited `crypto.ca.stats.view` /
/// `crypto.ca.certificates.view` set-and-proceed; every count carries `as_of` and its window.

#include <yuzu/server/auth.hpp>

#include "audited_write.hpp" // WriteGate (same-site gate for the layout PUT)
#include "authz_gates.hpp" // authz::FleetReadGate
#include "crypto_api.hpp"
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
    /// The NON-auditing probe (`AuthRoutes::has_permission`): decides what to DRAW only, never a
    /// gate.
    using HasPermFn = std::function<bool(const httplib::Request&, const std::string& securable_type,
                                         const std::string& operation)>;

    struct Deps {
        AuthFn auth_fn;
        /// The SOLE gate on every library data route. Empty = misconfigured -> 503 (fail closed).
        FleetReadFn fleet_read_fn;
        /// Nullable: a null seam answers 503 / the degrade banner, never an empty result.
        CryptoApiPtr api;
        AuditFn audit_fn;
        /// The SOLE gate on the Yuzu-issued routes (`Security:Read`, the same gate as
        /// `GET /api/v1/ca/issued`). Empty = misconfigured -> 503 (fail closed).
        PermFn perm_fn;
        /// `GET /api/v1/crypto/widgets`' per-widget `available` flag. Empty -> 503.
        HasPermFn has_perm_fn;
        /// Same-site gate of the layout PUT (cookie callers must name this site).
        WriteGate write_gate;
    };

    /// Production overload - wraps `httplib::Server&` in an HttplibRouteSink.
    void register_routes(httplib::Server& svr, Deps deps);

    /// Sink-based overload - used by tests (tests/unit/server/test_route_sink.hpp).
    void register_routes(HttpRouteSink& sink, Deps deps);

private:
    Deps deps_;
};

} // namespace yuzu::server
