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

#include <string>

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
/// unreadable / oversized / non-RSA cert or key — still disable SAML *loudly*
/// in server.cpp and are NOT gate-checked here, exactly as OIDC issuer/JWKS
/// runtime validity is not.
///
/// Why SAML is excluded on Windows: the SAML provider is a compile-time stub on
/// `_WIN32` (`is_enabled()` always false, `saml_provider_` never constructed),
/// so a complete SAML config there can never mint a session; counting it would
/// boot into the same lockout. Running the Yuzu *server* on Windows is out of
/// scope regardless (the managed-endpoint agent is unaffected).
bool sso_only_boot_guard_ok(const Config& cfg, std::string& err);

}  // namespace yuzu::server
