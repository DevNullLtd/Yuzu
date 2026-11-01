#pragma once

// sso_boot_guard.hpp — testable core of the `--auth-mode=sso-only` (hardened
// mode) boot guard, SOC 2 CC6.3.
//
// Hardened mode disables the local-password login path fleet-wide, so the
// server MUST refuse to start unless at least one SSO provider can actually
// mint a session — otherwise every operator is locked out (the break-glass
// account is for an IdP OUTAGE, not for never wiring SSO at all). Extracted
// from main.cpp so the OIDC/SAML/HTTPS/platform preconditions have direct unit
// coverage instead of only being exercised end-to-end by booting a server.
// Mirrors `scim_boot_guard_ok` (scim_routes.hpp): a thin main-side wrapper logs
// `err` and returns EXIT_FAILURE.
//
// The two per-provider predicates below are ALSO the single source of truth for
// "is this provider configured", shared with server.cpp's SAML wiring — a
// second inlined copy is exactly the drift this seam removes.

#include <expected>
#include <string>

namespace yuzu {
class MetricsRegistry;
}

namespace yuzu::server {

struct Config;

/// OIDC is "configured enough to mint a session" when BOTH the issuer and the
/// client-id are set — the SAME predicate `oidc::Config::is_enabled()` uses
/// (oidc_provider.hpp), so a `--oidc-issuer` with no `--oidc-client-id` (SSO
/// silently non-functional) does NOT satisfy the gate (review #1735 HIGH-1).
bool oidc_config_complete(const Config& cfg);

/// SAML SP config is "complete" when all five endpoint/identity fields are set.
/// PURE config presence — mirrors `SamlProvider::is_enabled()`'s field set and
/// the inlined check in server.cpp's SAML wiring (both now call this). It
/// deliberately does NOT fold in HTTPS or the platform: server.cpp needs the
/// bare 5-field predicate to distinguish a partial-config *warning* from the
/// separate HTTPS-disabled *error*, and the boot guard folds HTTPS + platform
/// in at the aggregate level (`sso_only_boot_guard_ok`).
bool saml_config_complete(const Config& cfg);

/// Returns true (leaving `err` untouched) when the configuration is safe to
/// boot with: `--auth-mode` is NOT "sso-only", OR it is and at least one SSO
/// provider can mint a session — OIDC configured, or (non-Windows) SAML
/// configured AND HTTPS enabled. Returns false with a human-readable `err`
/// otherwise. Never touches disk/network — pure config validation.
///
/// Why HTTPS is folded into the SAML term (not deferred to runtime): server.cpp
/// leaves `saml_provider_` null under `--no-https` (the Secure browser-binding
/// cookie is dropped over plain HTTP, so `/auth/saml/start` 404s). A SAML-only
/// `--no-https` deployment would pass a presence-only gate and boot straight
/// into a fleet-wide lockout. HTTPS is a deterministic Config field, so gating
/// on it mirrors "the same predicate the provider uses to enable itself"
/// exactly as the OIDC leg does. The genuinely runtime SAML failure modes — an
/// unreadable / oversized / unloadable IdP cert, or a bad / non-RSA SP key —
/// still disable SAML *loudly* in server.cpp and are NOT gate-checked HERE (this
/// function is pure and runs before the providers exist); they are caught one
/// step later by
/// `sso_only_runtime_providers_ok` below (#4160). OIDC issuer/JWKS reachability
/// is NOT checked at either step — see that function's deliberate limits.
///
/// Why SAML is excluded on Windows: the SAML provider is a compile-time stub on
/// `_WIN32` (`is_enabled()` always false, `saml_provider_` never constructed),
/// so a complete SAML config there can never mint a session; counting it would
/// boot into the same lockout. Running the Yuzu *server* on Windows is out of
/// scope regardless (the managed-endpoint agent is unaffected).
bool sso_only_boot_guard_ok(const Config& cfg, std::string& err);

/// RUNTIME-WIRING half of the sso-only guard (#4160). `sso_only_boot_guard_ok`
/// above runs in main.cpp BEFORE `Server::create` and is pure config presence;
/// this one runs inside the `ServerImpl` constructor AFTER the OIDC and SAML
/// providers have been wired, when "configured" has become "actually
/// constructed and enabled". `oidc_up` / `saml_up` are that outcome (provider
/// non-null and `is_enabled()`), so a present-but-unusable SAML credential — an
/// unreadable, oversized or unloadable IdP certificate, or a bad SP signing
/// key — no longer boots into a fleet-wide lockout.
///
/// Returns success when `--auth-mode` is NOT "sso-only", or when AT LEAST ONE
/// provider is up: one working provider means operators can still sign in, so a
/// broken secondary is a loud log line plus `..._provider_configured == 1` with
/// `..._provider_enabled == 0` on its gauges, not a refusal. Returns the
/// human-readable reason when neither is up.
///
/// Deliberate limits (do not widen without re-opening #4160):
///  * LOCAL ONLY — no network. OIDC discovery/JWKS is lazy (first use, #5692) and
///    stays that way: an IdP outage during a restart must NOT block boot, because
///    break-glass is the documented recovery for exactly that outage.
///  * The OIDC leg is thin by construction. In the shipped binary
///    `--oidc-nat64-prefix` is validated at flag-parse time (main.cpp), so wiring
///    leaves OIDC null only for a `Config` assembled outside the CLI; the real
///    work of this check is the SAML leg. Both providers are still judged by the
///    SAME predicate ("did wiring leave a usable provider"), so neither is
///    treated as more trustworthy than the other.
///  * Break-glass is NOT an SSO provider and never satisfies this check — it is
///    the recovery path for a runtime outage, not a substitute for wiring SSO.
///  * A refusal stops the WHOLE server (agent gRPC plane and API-token
///    automation included), not just operator sign-in: that is what "refuses to
///    start" means in this codebase. Hence the explicit cause + recovery text.
[[nodiscard]] std::expected<void, std::string>
sso_only_runtime_providers_ok(const Config& cfg, bool oidc_up, bool saml_up);

/// Publish `yuzu_auth_oidc_provider_configured` / `..._enabled` (0/1 gauges).
/// `configured` is config presence; `enabled` is "constructed and
/// is_enabled()". `configured == 1 && enabled == 0` is the exact signal
/// "configured but disabled at runtime" (#4160), independent of auth mode.
/// ONE publisher shared by the boot wiring (server.cpp) and the Settings OIDC
/// save (settings_routes.cpp), so a runtime reconfigure cannot leave the gauge
/// stale; `describe` is idempotent.
void publish_oidc_provider_gauges(yuzu::MetricsRegistry& metrics, bool configured, bool enabled);

/// SAML twin of `publish_oidc_provider_gauges`. `enabled` is always 0 on
/// Windows, where the SAML provider is a compile-time stub.
void publish_saml_provider_gauges(yuzu::MetricsRegistry& metrics, bool configured, bool enabled);

}  // namespace yuzu::server
