#pragma once

// Pure renderers for the four Security-page panels (SSO, two-factor, dashboard HTTPS, agent
// mTLS). Each takes a plain view struct and returns an HTML fragment, so the markup contract is
// testable with no routes, stores or sessions. SettingsRoutes::render_*_fragment build the view
// from cfg_ / the auth store and call these.
//
// Page rules (CSP and the redesign): no `hx-on`, no inline `on*=` handlers, no secret ever in a
// `value=` attribute, every dynamic string through html_escape. Fragment URLs, container ids
// (#directory-section, #mfa-section, #https-section, #tls-section) and POST field names are the
// ones /settings has always used, so the same fragments serve both pages.

#include <string>
#include <vector>

namespace yuzu::server::security_render {

struct HttpsView {
    bool enabled{false};
    int port{0};
    std::string cert_path;
    std::string key_path;
    bool redirect{false};
};
std::string render_https(const HttpsView& v);

struct TlsView {
    bool enabled{false};
    std::string cert_path, key_path, ca_path;
    bool insecure_skip_client_verify{false};
    std::string mgmt_cert_path, mgmt_key_path, mgmt_ca_path;
};
std::string render_tls(const TlsView& v);

enum class SsoState { kRunning, kSavedNotRunning, kNotConfigured };

struct DirectoryView {
    std::string issuer, client_id, redirect_uri, admin_group;
    bool secret_stored{false};
    bool skip_tls_verify{false};
    SsoState state{SsoState::kNotConfigured};
    /// Shown INSIDE #oidc-feedback (an out-of-band swap into it is destroyed by the main swap).
    std::string message;
    bool message_is_error{true};
};
std::string render_directory(const DirectoryView& v);

enum class MfaKind {
    kStoreUnavailable,  ///< no AuthDB configured
    kSsoManaged,        ///< session identity is an IdP principal; no local two-factor
    kStatusUnavailable, ///< store error: state unknown, retry
    kUserNotFound,
    kNotEnrolled,
    kProvisional, ///< enrolment started, code not yet confirmed
    kEnrolled,
};

struct MfaView {
    MfaKind kind{MfaKind::kNotEnrolled};
    std::string error_msg;
    // Provisional: first reveal carries the secret; a retry after a wrong code does not.
    std::string otpauth_uri, secret_b32, qr_svg;
    // Not enrolled / enrolled.
    std::string enrolled_at, disabled_at;
    int recovery_codes_remaining{0};
    std::vector<std::string> new_recovery_codes; ///< one-time reveal
    std::string enforcement_mode;                ///< "optional" | "admin-only" | "required"
    bool enforcement_protects{false};            ///< the route would refuse Disable/Cancel
};
std::string render_mfa(const MfaView& v);

// Confirm strings, exposed so tests pin the exact wording the operator reads.
extern const char* const kConfirmSaveSso;
extern const char* const kConfirmMtls;
extern const char* const kConfirmRegenerateCodes;
extern const char* const kConfirmDisableMfa;

} // namespace yuzu::server::security_render
