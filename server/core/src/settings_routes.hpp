#pragma once

/// @file settings_routes.hpp
/// Extracted from server.cpp — Settings page HTMX routes, fragment renderers,
/// and YAML helpers.  Phase 1 of the god-object decomposition.

#include <yuzu/metrics.hpp>
#include <yuzu/server/auth.hpp>
#include <yuzu/server/auto_approve.hpp>

#include "api_token_store.hpp"
#include "audit_store.hpp"
#include "engine_principal_store.hpp"
#include "management_group_store.hpp"
#include "mfa_step_up.hpp"
#include "oidc_provider.hpp"
#include "runtime_config_store.hpp"
#include "tag_store.hpp"
#include "update_registry.hpp"

#include <httplib.h>

#include <cstddef>
#include <functional>
#include <memory>
#include <optional>
#include <shared_mutex>
#include <string>
#include <vector>

namespace yuzu::server {

struct Config;
class RbacStore;
class AccessReviewStore;
class DirectorySync;
class ScimStore;

/// Settings page routes — all /settings, /fragments/settings/*, /api/settings/* routes.
class SettingsRoutes {
public:
    using AuthFn =
        std::function<std::optional<auth::Session>(const httplib::Request&, httplib::Response&)>;
    using AdminFn = std::function<bool(const httplib::Request&, httplib::Response&)>;
    using PermFn =
        std::function<bool(const httplib::Request&, httplib::Response&,
                           const std::string& securable_type, const std::string& operation)>;
    using AuditFn = std::function<void(const httplib::Request&, const std::string& action,
                                       const std::string& result, const std::string& target_type,
                                       const std::string& target_id, const std::string& detail)>;

    /// #4028 — bool-returning audit hook for the fail-closed REST read-twins
    /// (`GET /api/v1/settings/tls|https|plugin-signing|analytics` +
    /// `GET /api/v1/agent/plugin-policy`). Distinct from `AuditFn` above
    /// (fire-and-forget void, used by every existing dashboard-fragment
    /// mutation in this class) because docs/api-twin-recipe.md §4 requires a
    /// REST JSON read to FAIL CLOSED (503) on an audit-persist failure,
    /// which needs the real persisted-or-not bool that `rest_audit.hpp`'s
    /// `try_persist_audit`/`emit_behavioral_audit` return — `AuditFn`'s void
    /// return erases that. Optional (defaults empty): when unset, calling
    /// `try_persist_audit`/`emit_behavioral_audit` with it behaves exactly
    /// like an audit-off deployment (returns `true`, never blocks a read) —
    /// see `rest_audit.hpp`'s "null/empty audit_fn is not a persistence
    /// failure" contract. Not all 8 sub-areas are wired to it: only the four
    /// judged high/mixed-high sensitivity in #4028's Evidence section
    /// (tls, https, plugin-signing, analytics) call it; the other four
    /// (gateway, server-config, mcp, data-retention — "nothing secret" per
    /// the same Evidence section) issue no audit call at all, matching the
    /// unaudited posture the existing `/fragments/settings/*` HTML renderers
    /// for those four already have today.
    using AuditReadFn =
        std::function<bool(const httplib::Request&, const std::string& action,
                           const std::string& result, const std::string& target_type,
                           const std::string& target_id, const std::string& detail)>;

    /// Callback to get agents JSON from AgentRegistry (avoids incomplete-type dep).
    using AgentsJsonFn = std::function<std::string()>;

    /// Callback to get gateway session count (avoids incomplete-type dep).
    using GatewaySessionCountFn = std::function<std::size_t()>;

    /// F1: callback the DEX-alerts POST handlers invoke after persisting a
    /// change, so the live router/detector pick it up without a restart.
    /// Wired by server.cpp after registration, BEFORE the listener starts
    /// (so no request can race the set). May stay empty (tests) — the
    /// handlers then persist without the live apply.
    void set_dex_alert_apply_fn(std::function<void()> fn) { dex_alert_apply_fn_ = std::move(fn); }

    /// Inject the engine-principal store (nullable — a null pointer means
    /// the feature is not yet wired; server.cpp wiring is a separate task
    /// from this one, same deferral pattern as `AuthRoutes::
    /// set_engine_principal_store`). While unset, the DELETE-user
    /// owner-delete guard (design doc §3.1) and the Engine Principals
    /// admin-console fragment are both skipped/inert. Setter rather than a
    /// ctor param to keep the stacked-PR wiring in server.cpp low-risk.
    void set_engine_principal_store(EnginePrincipalStore* store) {
        engine_principal_store_ = store;
    }

    /// Inject the RBAC store (nullable — same deferred-wiring pattern as
    /// `set_engine_principal_store` above; server.cpp wiring is a separate
    /// follow-up task). Required by `access_review_model::build_access_review`
    /// for the Access Reviews Settings fragment (SOC 2 CC6.2); while unset,
    /// that fragment renders its "data unavailable" notice instead of
    /// crashing (build_access_review returns `std::unexpected` on a null/
    /// closed RbacStore — see access_review_model.hpp).
    void set_rbac_store(RbacStore* store) { rbac_store_ = store; }

    /// Inject the Access Review campaign store (nullable, same deferred-
    /// wiring pattern). Backs the campaign-view sub-fragment
    /// (`render_access_review_campaign_fragment`) — while unset, that
    /// fragment renders a "store unavailable" notice. The fragment's write
    /// actions (open/attest/close) do NOT go through this pointer — they
    /// call the REST endpoints in rest_api_v1.cpp directly (the ADR-1005
    /// API-parity surface), so this pointer is read-only-path use only.
    void set_access_review_store(AccessReviewStore* store) { access_review_store_ = store; }

    /// Inject DirectorySync for the access-review read-model's optional
    /// user-email enrichment (nullable — see access_review_model.hpp's
    /// "optional enrichment" contract; a null pointer degrades only the
    /// `owner_or_email` field, never fails the export). Same deferred-wiring
    /// pattern as the setters above.
    void set_access_review_directory_sync(DirectorySync* dirsync) { directory_sync_ = dirsync; }

    /// Inject ScimStore (nullable, same deferred-wiring pattern as the
    /// setters above). ADR-2001 §§1,3: `DELETE /api/settings/users/
    /// {username}` resolves the deleted username's SCIM slug -> linked-OIDC
    /// principal set through this pointer before revoking credentials.
    /// While unset (or not open), the resolver degrades to the slug-only
    /// set rather than failing closed — see `deprovision_revoke.hpp`'s
    /// `resolve_deprovision_principals_for_username` doc comment.
    void set_scim_store(ScimStore* store) { scim_store_ = store; }

    /// Register all settings-related routes on the given server.
    /// Production callers use this overload; internally it constructs an
    /// HttplibRouteSink and delegates to the sink-based overload below.
    ///
    /// `metrics_registry` (optional, may be null) — when non-null the HTMX
    /// token-create handler increments
    /// `yuzu_secure_random_failure_total{site="api_token_htmx"}` on CSPRNG
    /// entropy-exhaustion failures so on-call has a paging signal short of
    /// grepping audit logs (sre-1 on PR W1.1).
    void register_routes(httplib::Server& svr, AuthFn auth_fn, AdminFn admin_fn, PermFn perm_fn,
                         AuditFn audit_fn, Config& cfg, auth::AuthManager& auth_mgr,
                         auth::AutoApproveEngine& auto_approve, ApiTokenStore* api_token_store,
                         ManagementGroupStore* mgmt_group_store, TagStore* tag_store,
                         UpdateRegistry* update_registry, RuntimeConfigStore* runtime_config_store,
                         AuditStore* audit_store, bool gateway_enabled,
                         GatewaySessionCountFn gateway_session_count_fn,
                         AgentsJsonFn agents_json_fn, std::shared_mutex& oidc_mu,
                         std::unique_ptr<oidc::OidcProvider>& oidc_provider,
                         yuzu::MetricsRegistry* metrics_registry = nullptr,
                         StepUpFn step_up_fn = {}, AuditReadFn audit_read_fn = {});

    /// Sink-based overload — used by tests to register routes against an
    /// in-process TestRouteSink and dispatch synthesized requests directly,
    /// avoiding httplib::Server's TSan-hostile acceptor thread (#438).
    ///
    /// `step_up_fn` (PR2, optional) — when present, the 2 user-management
    /// Settings mutations (DELETE user, POST user role) gate behind it
    /// after admin_fn passes. Empty functor disables the gate entirely.
    void register_routes(class HttpRouteSink& sink, AuthFn auth_fn, AdminFn admin_fn,
                         PermFn perm_fn, AuditFn audit_fn, Config& cfg, auth::AuthManager& auth_mgr,
                         auth::AutoApproveEngine& auto_approve, ApiTokenStore* api_token_store,
                         ManagementGroupStore* mgmt_group_store, TagStore* tag_store,
                         UpdateRegistry* update_registry, RuntimeConfigStore* runtime_config_store,
                         AuditStore* audit_store, bool gateway_enabled,
                         GatewaySessionCountFn gateway_session_count_fn,
                         AgentsJsonFn agents_json_fn, std::shared_mutex& oidc_mu,
                         std::unique_ptr<oidc::OidcProvider>& oidc_provider,
                         yuzu::MetricsRegistry* metrics_registry = nullptr,
                         StepUpFn step_up_fn = {}, AuditReadFn audit_read_fn = {});

private:
    // -- Fragment renderers (called by route handlers) -------------------------

    std::string render_server_config_fragment();
    std::string render_tls_fragment();
    /// Render the Users settings fragment.
    ///
    /// @param current_username  Username of the currently authenticated
    ///                          operator. The row matching this name is
    ///                          rendered without a "Remove" button to
    ///                          prevent self-deletion lockout (#397/#403).
    ///                          No default is provided — every caller must
    ///                          pass an explicit value (typically
    ///                          `session->username`) so a future call site
    ///                          omitting the argument is a compile error,
    ///                          not a silent UI regression that re-renders
    ///                          the pre-fix Remove button on the self row.
    std::string render_users_fragment(const std::string& current_username);
    std::string render_tokens_fragment(const std::string& new_raw_token = {});
    /// Render the API tokens settings fragment.
    ///
    /// @param new_raw_token   Raw token value just minted (displayed once), or empty.
    /// @param filter_principal When non-empty, list only tokens owned by this
    ///                         principal. Empty = show every token (admin view).
    ///                         Callers must pass session->username for non-admin
    ///                         sessions to prevent cross-user token enumeration
    ///                         (governance Gate 4 finding C1).
    std::string render_api_tokens_fragment(const std::string& new_raw_token = {},
                                           const std::string& filter_principal = {});
    /// Render the per-user MFA / TOTP self-service panel. Shows current
    /// status (enrolled / not enrolled / disabled), recovery-codes-remaining,
    /// and the operative buttons (enroll / disable / regenerate codes).
    /// Optional `otpauth_uri` / `secret_b32` / `recovery_codes` are populated
    /// by the POST handlers for the one-time reveal after enroll / verify /
    /// regenerate. SOC 2 CC6.6 — see docs/auth-mfa-design.md.
    std::string render_mfa_fragment(const std::string& username,
                                    const std::string& new_otpauth_uri = {},
                                    const std::string& new_secret_b32 = {},
                                    const std::vector<std::string>& new_recovery_codes = {},
                                    const std::string& enrollment_pending_for_verify = {},
                                    const std::string& error_msg = {});

    std::string render_pending_fragment();
    std::string render_auto_approve_fragment();
    std::string render_tag_compliance_fragment();
    std::string render_management_groups_fragment();
    std::string render_updates_fragment();
    std::string render_gateway_fragment();
    std::string render_https_fragment();
    std::string render_analytics_fragment();
    std::string render_data_retention_fragment();
    /// F1 DEX alerting — per-signal routing checkboxes (rendered from the
    /// dex_signal_groups() catalogue) + the blast-radius alert-shape trio.
    /// State lives in runtime_config; applied live via dex_alert_apply_fn_.
    std::string render_dex_alerts_fragment();
    std::string render_mcp_fragment();
    std::string render_nvd_fragment();
    std::string render_directory_fragment();
    /// Plugin code-signing settings — operator-managed trust bundle and
    /// require-signature toggle. The PEM bundle lives in
    /// auth::default_cert_dir() / "plugin-trust-bundle.pem"; the require
    /// flag persists in `runtime_config` under key
    /// "plugin_signing_required". Bundle metadata (cert count, SHA-256)
    /// is recomputed at render time directly from the PEM file rather
    /// than denormalised, to avoid drift between disk + DB.
    std::string render_plugin_signing_fragment();
    /// Render the Engine Principals admin-console fragment — a table of
    /// every engine principal (`EnginePrincipalStore::list_all`, including
    /// revoked rows) with owner, classification, lifecycle state, and
    /// active-credential count (`ApiTokenStore::list_active_for_principal`).
    /// Revoked rows surface the `superseded_by` linkage AND the revocation
    /// reason explicitly (design doc §3.1) — never a merged history that
    /// hides that a revocation occurred. Admin-only; a null
    /// `engine_principal_store_` renders an inert "not configured" panel.
    std::string render_engine_principals_fragment();

    /// Render the Access Reviews Settings fragment (SOC 2 CC6.2) — a
    /// CONVENIENCE dashboard surface only; the REST endpoints under
    /// `/api/v1/access-reviews*` (rest_api_v1.cpp) and their MCP twins are
    /// the ADR-1005 API-parity surface. Shows the current cross-principal
    /// grant export (`access_review_model::build_access_review`) + a CSV
    /// download link; an operator holding `AccessReview:Attest` additionally
    /// sees the "open review campaign" control (probed via a throwaway
    /// `httplib::Response`, mirroring `dex_routes.cpp`'s `can_execute`
    /// pattern — never gates the whole route on Attest, since a read-only
    /// auditor must still see the table). `req` is needed for that probe.
    std::string render_access_review_fragment(const httplib::Request& req);

    /// Render one review campaign's evidentiary state (metadata + frozen
    /// attestation rows) as a sub-fragment — used both for the initial
    /// `?id=` deep link and for the JS-driven refresh after an attest/flag/
    /// close action. Gated by the caller on `AccessReview:Read` (matches the
    /// REST `GET /api/v1/access-reviews/{id}` gate); per-row Attest/Flag
    /// buttons and the Close-campaign button are additionally probed against
    /// `AccessReview:Attest` inside this function, same pattern as the top-level
    /// fragment above. Empty `campaign_id` renders an empty container.
    std::string render_access_review_campaign_fragment(const httplib::Request& req,
                                                        const std::string& campaign_id);

    // -- Dependency pointers (stored by register_routes) -----------------------

    AuthFn auth_fn_;
    AdminFn admin_fn_;
    PermFn perm_fn_;
    AuditFn audit_fn_;
    AuditReadFn audit_read_fn_; // #4028 — fail-closed REST audit hook, see AuditReadFn doc comment
    std::function<void()> dex_alert_apply_fn_; // F1 live-apply hook (may be empty)
    Config* cfg_{};
    auth::AuthManager* auth_mgr_{};
    auth::AutoApproveEngine* auto_approve_{};
    ApiTokenStore* api_token_store_{};
    // Nullable — see set_engine_principal_store(). Non-owning; lifetime is
    // server.cpp's, which outlives this object.
    EnginePrincipalStore* engine_principal_store_{nullptr};
    // Nullable — see set_rbac_store() / set_access_review_store() /
    // set_access_review_directory_sync(). Non-owning; lifetime is
    // server.cpp's, which outlives this object.
    RbacStore* rbac_store_{nullptr};
    AccessReviewStore* access_review_store_{nullptr};
    DirectorySync* directory_sync_{nullptr};
    // Nullable — see set_scim_store(). Non-owning; lifetime is server.cpp's,
    // which outlives this object.
    ScimStore* scim_store_{nullptr};
    ManagementGroupStore* mgmt_group_store_{};
    TagStore* tag_store_{};
    UpdateRegistry* update_registry_{};
    RuntimeConfigStore* runtime_config_store_{};
    AuditStore* audit_store_{};
    bool gateway_enabled_{};
    GatewaySessionCountFn gateway_session_count_fn_;
    AgentsJsonFn agents_json_fn_;
    std::shared_mutex* oidc_mu_{};
    std::unique_ptr<oidc::OidcProvider>* oidc_provider_{};
    yuzu::MetricsRegistry* metrics_registry_{};
    StepUpFn step_up_fn_;
};

} // namespace yuzu::server
