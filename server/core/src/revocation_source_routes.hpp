#pragma once

/// @file revocation_source_routes.hpp
/// `/api/v1/crypto/revocation-sources` - the registered-CRL-source surface (ADR-0070 R1, slice
/// 2b-1a): list, get, register, replace, remove and reset-high-water. One route owner; the MCP
/// twins (`mcp_server.cpp`) call the SAME `RevocationSourceService`, so the two transports accept
/// and refuse exactly the same bodies.
///
/// GATE, in order, on every route: `auth_fn`; then `perm_fn` for `RevocationSource:Read` (list,
/// get) or `RevocationSource:Write` (everything else - removal and the reset are a `Write`, there
/// is no `Delete`); then `admin_fn`, the durable administrator predicate
/// (`revocation_source_admin_gate.hpp`). The surface is admin-only in BOTH RBAC states and so not
/// grantable: a custom role holding the securable is still refused by `admin_fn`. A service-scoped
/// token is refused by both gates in either state. An unwired `perm_fn`, `admin_fn` or service
/// fails closed (503). The four mutations then pass MFA step-up (`step_up_fn`; kRequired rows in
/// `step_up_policy.hpp`, enforced by the pre-routing chokepoint AND in the handler) and the
/// same-site rule for a cookie session.
///
/// AUDIT: reads emit `crypto.revocation_source.list` / `.view` and FAIL CLOSED on REST (a row that
/// does not persist answers 503 + `Sec-Audit-Failed` with no data). Mutations emit
/// `.register` / `.update` / `.remove` / `.reset_high_water` with "no audit row, no mutation": an
/// `attempted` row is written first and a failure to store it refuses the change (503); the
/// outcome row follows and a lost outcome row keeps the 2xx, marks the response
/// `Sec-Audit-Failed` and sets `audit_persisted: false` (an `attempted` row with no outcome row
/// means the outcome was not recorded, NOT that the change did not happen). Every
/// operator-supplied value in a detail passes `log_token`.
///
/// Every response is per-caller and `Cache-Control: no-store, private`. Errors are the A4
/// envelope; a 409 names the existing source in its remediation.

#include <yuzu/server/auth.hpp>

#include "audited_write.hpp" // WriteGate (same-site gate on the mutations)
#include "http_route_sink.hpp"
#include "revocation_source_service.hpp"

#include <httplib.h>

#include <functional>
#include <optional>
#include <string>

namespace yuzu::server {

class RevocationSourceRoutes {
public:
    using AuthFn =
        std::function<std::optional<auth::Session>(const httplib::Request&, httplib::Response&)>;
    using AuditFn = std::function<bool(const httplib::Request&, const std::string& action,
                                       const std::string& result, const std::string& target_type,
                                       const std::string& target_id, const std::string& detail)>;
    /// The auditing permission gate (`require_permission`): writes 401/403/503 and returns false.
    using PermFn = std::function<bool(const httplib::Request&, httplib::Response&,
                                      const std::string& securable_type,
                                      const std::string& operation)>;
    /// The MFA step-up gate (`mfa_step_up.hpp`'s `StepUpFn`, restated so this TU needs not include
    /// it): writes 401 and returns false when an enrolled caller's proof is stale. Empty =
    /// pass-through (a test seam; server.cpp always wires the shared closure).
    using StepUpFn = std::function<bool(const httplib::Request&, httplib::Response&,
                                        const auth::Session&, const std::string& action_label)>;
    /// The administrator decision for the session; `is_write` selects the regime re-check.
    using AdminFn =
        std::function<revocation_source::AdminDecision(const auth::Session&, bool is_write)>;

    struct Deps {
        AuthFn auth_fn;
        AuditFn audit_fn;
        PermFn perm_fn;
        AdminFn admin_fn;
        /// Same-site gate of the mutations (cookie callers must name this site).
        WriteGate write_gate;
        /// MFA step-up on the four mutations, with the action labels `step_up_policy.hpp` carries
        /// for them (the pre-routing chokepoint evaluates the same table row first).
        StepUpFn step_up_fn;
        /// Nullable: a null service answers 503, never an empty result.
        revocation_source::RevocationSourceService* service{nullptr};
    };

    /// Production overload - wraps `httplib::Server&` in an HttplibRouteSink.
    void register_routes(httplib::Server& svr, Deps deps);

    /// Sink-based overload - used by tests (tests/unit/server/test_route_sink.hpp).
    void register_routes(HttpRouteSink& sink, Deps deps);

private:
    Deps deps_;
};

} // namespace yuzu::server
