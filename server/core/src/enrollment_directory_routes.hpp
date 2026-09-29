#pragma once

/// @file enrollment_directory_routes.hpp
///
/// #4031 (API-parity Batch A) REST v1 read twins for the five previously
/// untwinned GET routes `scripts/ci/api-parity/enrollment.json` carried at
/// `planned:#2146`:
///   - GET /api/v1/directory/users             (twin of legacy GET /api/directory/users)
///   - GET /api/v1/directory/status            (twin of legacy GET /api/directory/status)
///   - GET /api/v1/enrollment/auto-approve-rules (twin of GET /fragments/settings/auto-approve)
///   - GET /api/v1/enrollment/pending-agents     (twin of GET /fragments/settings/pending)
///   - GET /api/v1/settings/oidc                 (twin of GET /fragments/settings/directory —
///     see the naming-trap note below)
///
/// Every row's JSON shape comes from `enrollment_directory_model.hpp`'s
/// shared builder functions, per docs/api-twin-recipe.md §1 — but the
/// dashboard fragments (settings_routes.cpp) do NOT call them today; only
/// `directory_user_row_json`/`directory_status_json` are genuinely
/// multi-consumer (REST v1 + the two new MCP tools + the legacy
/// `/api/directory/*` route). See `enrollment_directory_model.hpp`'s file
/// header for the accurate 2-of-5 scope and why that matters.
///
/// #520 DECISION (prerequisite 2 of the #4031 issue, same policy question as
/// the sibling settings issue #4028): the three previously admin_fn_-gated
/// capabilities (auto-approve rules, pending agents, OIDC config) ship
/// REST-only here — no MCP twin. `require_admin`'s own comment
/// (auth_routes.cpp) names "settings... OIDC" as things MCP tokens must not
/// administer; #4028 recommends the identical REST-only + exception:#520
/// posture for its own admin_fn_-gated settings fragments, and this PR does
/// not diverge from that without a stated reason. The two directory-sync
/// routes (users/status) were ALREADY gated by RBAC (`Directory:Read`), not
/// `admin_fn_`, so #520 does not apply to them — they get full MCP twins.
///
/// NAMING TRAP: `GET /api/v1/settings/oidc` gates on the freshly-minted
/// `OidcConfig` securable, never `Directory` — see
/// enrollment_directory_model.hpp's file header and discovery_routes.cpp's
/// directory-sync section for the full explanation. Its REST v1 path lives
/// under `/api/v1/settings/...` (not `/api/v1/directory/...`) specifically to
/// avoid the collision.
///
/// CONFINEMENT (ADR-0017, #4031 hardening — adversarial review of the branch
/// before push):
/// `GET /api/v1/enrollment/pending-agents` is the one route among these five
/// whose rows carry genuine per-agent identity (`agent_id`, hostname, os,
/// arch, agent_version — `auth::PendingAgent`) — the other four return
/// human-identity rows, aggregate metadata, or rule/config objects, none of
/// which ADR-0017 applies to. It therefore gates on `FleetReadFn`
/// (`AuthRoutes::require_fleet_read`, the admit-then-filter chokepoint),
/// NEVER `PermFn`, per `.claude/routed-concerns.md` row 1's MUST/never — see
/// the route's own comment in enrollment_directory_routes.cpp for the
/// under-admission scenario this closes (a management-group-scoped
/// `Enrollment:Read` grant was previously 403'd outright instead of admitted
/// with its real, confined result — typically empty, since pre-enrollment
/// agents normally hold no group membership yet, but NOT a data-model
/// guarantee: a pre-assigned membership row yields a non-empty, still
/// correctly-confined, result).

#include <yuzu/server/auth.hpp>
#include <yuzu/server/auto_approve.hpp>

#include "authz_gates.hpp" // authz::FleetReadGate — ADR-0017 confinement for pending-agents
#include "directory_sync.hpp"

#include <httplib.h>

#include <functional>
#include <optional>
#include <shared_mutex>
#include <string>

namespace yuzu::server {

class HttpRouteSink; // http_route_sink.hpp — avoid pulling httplib-sink machinery
struct Config;        // server.hpp — only ::oidc_* fields are read

/// Directory-sync + enrollment + OIDC-config REST v1 read-twin routes.
class EnrollmentDirectoryRoutes {
public:
    using AuthFn =
        std::function<std::optional<auth::Session>(const httplib::Request&, httplib::Response&)>;
    using PermFn =
        std::function<bool(const httplib::Request&, httplib::Response&,
                           const std::string& securable_type, const std::string& operation)>;
    /// Bool-returning per docs/api-twin-recipe.md §4 (rest_audit.hpp's
    /// try_persist_audit/emit_behavioral_audit contract) — NOT the void
    /// fire-and-forget AuditFn some older route classes (DiscoveryRoutes,
    /// SettingsRoutes) still carry.
    using AuditFn = std::function<bool(const httplib::Request&, const std::string& action,
                                       const std::string& result, const std::string& target_type,
                                       const std::string& target_id, const std::string& detail)>;
    /// #4031 hardening: ADR-0017 admit-then-filter chokepoint
    /// (`AuthRoutes::require_fleet_read`), the injected-callback seam
    /// `RestApiV1`/`McpServer` already use (`rest_api_v1.hpp`'s own
    /// `FleetReadFn` — this is a second, identical typedef rather than a
    /// shared one because that header pulls in far more than this class
    /// needs; the underlying gate is the SAME shared `AuthRoutes` method,
    /// never reimplemented). MUST be `pending-agents`'s SOLE gate — never
    /// stacked with `PermFn` (see `authz_gates.hpp`'s own doc comment for
    /// why pairing them makes the `AdmitScoped` branch permanently
    /// unreachable). Default `{}` exists ONLY for source-stability of the
    /// OTHER four routes in this class, which stay on `PermFn` (none of them
    /// read per-agent data — see this file's CONFINEMENT header comment); a
    /// route that requires this gate treats an unwired fn as
    /// misconfiguration and fails closed (503), mirroring `FleetReadFn`'s
    /// contract everywhere else it's used.
    using FleetReadFn =
        std::function<authz::FleetReadGate(const httplib::Request&, httplib::Response&,
                                           const std::string& securable_type,
                                           const std::string& operation)>;

    /// Production entry point — wraps `svr` in HttplibRouteSink and delegates
    /// to the testable overload below (mirrors DiscoveryRoutes/DexRoutes).
    ///
    /// `oidc_mu` guards `cfg`'s `oidc_*` fields (SettingsRoutes' POST
    /// /api/settings/oidc handler takes `std::unique_lock(*oidc_mu_)` before
    /// reassigning them, settings_routes.cpp) — this class's GET
    /// /api/v1/settings/oidc handler takes `std::shared_lock` on the SAME
    /// mutex before reading them (Gate 5 chaos-injector finding, #4031
    /// hardening round: the original handler read these plain
    /// `std::string` fields with zero synchronization, a genuine data race
    /// under concurrent read/write — not merely a "no lock exists" gap,
    /// since ServerImpl already owns and threads this exact mutex into
    /// SettingsRoutes/AuthRoutes for this exact purpose).
    void register_routes(httplib::Server& svr, AuthFn auth_fn, PermFn perm_fn, AuditFn audit_fn,
                         DirectorySync* directory_sync, auth::AutoApproveEngine* auto_approve,
                         auth::AuthManager* auth_mgr, Config* cfg, std::shared_mutex& oidc_mu,
                         FleetReadFn fleet_read_fn = {});

    /// HttpRouteSink overload — used by tests to register routes against an
    /// in-process TestRouteSink and dispatch synthesised requests directly
    /// (no httplib::Server acceptor thread, the #438 TSan trap).
    void register_routes(HttpRouteSink& sink, AuthFn auth_fn, PermFn perm_fn, AuditFn audit_fn,
                         DirectorySync* directory_sync, auth::AutoApproveEngine* auto_approve,
                         auth::AuthManager* auth_mgr, Config* cfg, std::shared_mutex& oidc_mu,
                         FleetReadFn fleet_read_fn = {});
};

} // namespace yuzu::server
