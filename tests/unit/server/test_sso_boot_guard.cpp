/**
 * test_sso_boot_guard.cpp — unit coverage for the `--auth-mode=sso-only`
 * (hardened mode) boot guard, SOC 2 CC6.3 (sso_boot_guard.{hpp,cpp}).
 *
 * This is the first direct test of the hardened-mode boot gate: the check
 * itself lives inside main() and was previously only exercised end-to-end by
 * booting a server. The guard was extracted into a pure `const Config&`
 * predicate precisely so these cases can assert it directly — mirroring the
 * `scim_boot_guard_ok` (S-BOOTGUARD-TEST) pattern in test_scim_routes.cpp.
 *
 * Not PG-gated — pure config validation, no store/socket.
 */

#include "sso_boot_guard.hpp"

#include <yuzu/server/server.hpp>

#include <catch2/catch_test_macros.hpp>

#include <string>

using namespace yuzu::server;

namespace {

// A Config with OIDC fully configured (issuer + client-id) and nothing else.
Config oidc_ready() {
    Config cfg;
    cfg.auth_mode = "sso-only";
    cfg.oidc_issuer = "https://login.example.com/tenant/v2.0";
    cfg.oidc_client_id = "client-abc-123";
    return cfg;
}

// A Config with all five SAML SP fields set and HTTPS on, nothing else.
Config saml_ready() {
    Config cfg;
    cfg.auth_mode = "sso-only";
    cfg.https_enabled = true;
    cfg.saml_idp_entity_id = "https://idp.example.com/entity";
    cfg.saml_idp_sso_url = "https://idp.example.com/sso";
    cfg.saml_idp_cert = "/etc/yuzu/saml-idp.pem";
    cfg.saml_sp_entity_id = "https://yuzu.example.com/sp";
    cfg.saml_sp_acs_url = "https://yuzu.example.com/saml/acs";
    return cfg;
}

}  // namespace

// ── The predicates ──────────────────────────────────────────────────────────

TEST_CASE("oidc_config_complete: needs BOTH issuer and client-id", "[sso][bootguard]") {
    Config cfg;
    CHECK_FALSE(oidc_config_complete(cfg));
    cfg.oidc_issuer = "https://idp";
    CHECK_FALSE(oidc_config_complete(cfg)); // issuer alone is not enough (#1735 HIGH-1)
    cfg.oidc_client_id = "cid";
    CHECK(oidc_config_complete(cfg));
}

TEST_CASE("saml_config_complete: needs all five SP fields (HTTPS-agnostic)",
          "[sso][bootguard]") {
    Config cfg = saml_ready();
    CHECK(saml_config_complete(cfg));
    // The predicate is deliberately HTTPS-agnostic — server.cpp relies on that
    // to distinguish partial-config from the HTTPS-disabled error.
    cfg.https_enabled = false;
    CHECK(saml_config_complete(cfg));
    // Dropping any one field makes it incomplete.
    cfg.saml_sp_acs_url.clear();
    CHECK_FALSE(saml_config_complete(cfg));
}

// ── The guard — standard mode is never gated ────────────────────────────────

TEST_CASE("sso_only_boot_guard_ok: standard mode is always ok, provider or not",
          "[sso][bootguard]") {
    Config cfg; // auth_mode defaults to "standard"
    std::string err;
    CHECK(sso_only_boot_guard_ok(cfg, err));
    CHECK(err.empty());
}

// ── The guard — OIDC leg (all platforms) ────────────────────────────────────

TEST_CASE("sso_only_boot_guard_ok: sso-only + complete OIDC — ok", "[sso][bootguard]") {
    Config cfg = oidc_ready();
    std::string err;
    CHECK(sso_only_boot_guard_ok(cfg, err));
    CHECK(err.empty());
}

TEST_CASE("sso_only_boot_guard_ok: sso-only + OIDC issuer but no client-id — fails",
          "[sso][bootguard]") {
    Config cfg = oidc_ready();
    cfg.oidc_client_id.clear();
    std::string err;
    CHECK_FALSE(sso_only_boot_guard_ok(cfg, err));
    CHECK_FALSE(err.empty());
}

TEST_CASE("sso_only_boot_guard_ok: sso-only + no provider at all — fails", "[sso][bootguard]") {
    Config cfg;
    cfg.auth_mode = "sso-only";
    std::string err;
    CHECK_FALSE(sso_only_boot_guard_ok(cfg, err));
    CHECK_FALSE(err.empty());
}

TEST_CASE("sso_only_boot_guard_ok: complete OIDC does NOT require HTTPS at this gate",
          "[sso][bootguard]") {
    // The OIDC leg is unchanged by this feature — it never gated on HTTPS, so a
    // sso-only + OIDC + --no-https deployment still boots (HTTPS-by-default is a
    // separate, pre-existing global invariant). Lock that parity in.
    Config cfg = oidc_ready();
    cfg.https_enabled = false;
    std::string err;
    CHECK(sso_only_boot_guard_ok(cfg, err));
}

// ── The guard — SAML leg (non-Windows only; stub can't mint on Windows) ──────

#ifndef _WIN32

TEST_CASE("sso_only_boot_guard_ok: sso-only + complete SAML + HTTPS — ok (SAML-only, CC6.3)",
          "[sso][bootguard]") {
    Config cfg = saml_ready();
    REQUIRE(cfg.oidc_issuer.empty()); // truly SAML-only
    std::string err;
    CHECK(sso_only_boot_guard_ok(cfg, err));
    CHECK(err.empty());
}

TEST_CASE("sso_only_boot_guard_ok: sso-only + complete SAML but --no-https — fails (lockout guard)",
          "[sso][bootguard]") {
    Config cfg = saml_ready();
    cfg.https_enabled = false;
    std::string err;
    CHECK_FALSE(sso_only_boot_guard_ok(cfg, err));
    // Must fire the DEDICATED SAML+no-HTTPS branch, not the generic
    // no-provider fallthrough — assert on a phrase unique to that branch so a
    // future refactor deleting it can't pass vacuously (the generic message
    // also contains "HTTPS"). This is the exact lockout the gate prevents.
    CHECK(err.find("still requires HTTPS") != std::string::npos);
}

TEST_CASE("sso_only_boot_guard_ok: sso-only + partial SAML (missing one field) — fails",
          "[sso][bootguard]") {
    Config cfg = saml_ready();
    cfg.saml_idp_entity_id.clear();
    std::string err;
    CHECK_FALSE(sso_only_boot_guard_ok(cfg, err));
    CHECK_FALSE(err.empty());
}

TEST_CASE("sso_only_boot_guard_ok: sso-only + dual OIDC+SAML — ok", "[sso][bootguard]") {
    Config cfg = saml_ready();
    cfg.oidc_issuer = "https://login.example.com/tenant/v2.0";
    cfg.oidc_client_id = "client-abc-123";
    std::string err;
    CHECK(sso_only_boot_guard_ok(cfg, err));
    CHECK(err.empty());
}

#else  // _WIN32

TEST_CASE("sso_only_boot_guard_ok: sso-only + complete SAML — fails on Windows (stub can't mint)",
          "[sso][bootguard]") {
    // The SAML provider is a compile-time stub on Windows, so a complete SAML
    // config can never mint a session there — it must NOT satisfy the gate.
    // (Running the server on Windows is out of scope regardless.)
    Config cfg = saml_ready();
    std::string err;
    CHECK_FALSE(sso_only_boot_guard_ok(cfg, err));
    CHECK_FALSE(err.empty());
}

#endif
