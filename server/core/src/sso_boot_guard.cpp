#include "sso_boot_guard.hpp"

#include <yuzu/server/server.hpp>  // Config

namespace yuzu::server {

bool oidc_config_complete(const Config& cfg) {
    return !cfg.oidc_issuer.empty() && !cfg.oidc_client_id.empty();
}

bool saml_config_complete(const Config& cfg) {
    return !cfg.saml_idp_sso_url.empty() && !cfg.saml_idp_cert.empty() &&
           !cfg.saml_sp_entity_id.empty() && !cfg.saml_sp_acs_url.empty() &&
           !cfg.saml_idp_entity_id.empty();
}

bool sso_only_boot_guard_ok(const Config& cfg, std::string& err) {
    if (cfg.auth_mode != "sso-only")
        return true;

    // A configured OIDC provider satisfies the gate on every platform.
    if (oidc_config_complete(cfg))
        return true;

#ifndef _WIN32
    // SAML can mint a session only when its config is complete AND HTTPS is on
    // (server.cpp leaves the provider null under --no-https). On Windows the
    // SAML provider is a compile-time stub, so this whole branch is excluded —
    // a complete SAML config there never satisfies the gate. See the header.
    if (saml_config_complete(cfg) && cfg.https_enabled)
        return true;

    if (saml_config_complete(cfg) && !cfg.https_enabled) {
        // Point specifically at HTTPS — this is the exact SAML-only + --no-https
        // lockout the gate exists to prevent, and the operator has otherwise
        // wired SAML correctly.
        err = "--auth-mode=sso-only with a complete SAML config still requires HTTPS: "
              "the SAML provider is left disabled under --no-https (its Secure "
              "browser-binding cookie is silently dropped over plain HTTP, so "
              "/auth/saml/start would 404) and every operator would be locked out. "
              "Enable HTTPS (--https-cert / --https-key), or use --auth-mode=standard.";
        return false;
    }
#endif

#ifdef _WIN32
    // SAML is a compile-time stub on Windows, so it is never a remedy here —
    // naming it would send a Windows operator into a config loop (UP-4). OIDC only.
    err = "--auth-mode=sso-only disables local-password login but OIDC is not fully "
          "configured, so every operator would be locked out. Configure OIDC (need both "
          "--oidc-issuer and --oidc-client-id), or use --auth-mode=standard. (SAML is not "
          "available on Windows server builds.)";
#else
    err = "--auth-mode=sso-only disables local-password login but no SSO provider is "
          "fully configured, so every operator would be locked out. Configure OIDC "
          "(need both --oidc-issuer and --oidc-client-id) or SAML (need "
          "--saml-idp-sso-url, --saml-idp-cert, --saml-sp-entity-id, --saml-sp-acs-url "
          "and --saml-idp-entity-id, plus HTTPS enabled), or use --auth-mode=standard.";
#endif
    return false;
}

}  // namespace yuzu::server
