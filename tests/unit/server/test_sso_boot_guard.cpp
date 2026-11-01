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

#include <yuzu/metrics.hpp>

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

// ── Runtime-wiring half (#4160) ─────────────────────────────────────────────
//
// sso_only_runtime_providers_ok runs inside ServerImpl AFTER the providers are
// wired, taking the OUTCOME (up/down) rather than reading disk or network. Its
// callers feed it `provider && provider->is_enabled()`, so these cases pin the
// decision table directly. NOT covered here: the ServerImpl constructor wiring
// itself (which provider pointer feeds which flag, startup_failed_ being set) —
// ServerImpl is not unit-constructible (it needs Postgres); that wiring is
// guarded by the lexical tripwire tests/test_sso_runtime_wiring_lexical.py (a
// best-effort source-text check) plus a live boot, which is a manual step, not a
// test in this tree. The IdP-certificate probe that makes
// `saml_up` truthful is unit-tested in test_saml_provider.cpp ([4160]).

TEST_CASE("sso_only_runtime_providers_ok: standard mode is always ok", "[sso][bootguard][runtime]") {
    Config cfg;
    cfg.auth_mode = "standard";
    CHECK(sso_only_runtime_providers_ok(cfg, false, false).has_value());
}

TEST_CASE("sso_only_runtime_providers_ok: sso-only with a provider up is ok",
          "[sso][bootguard][runtime]") {
    CHECK(sso_only_runtime_providers_ok(oidc_ready(), true, false).has_value());
    CHECK(sso_only_runtime_providers_ok(saml_ready(), false, true).has_value());
}

TEST_CASE("sso_only_runtime_providers_ok: sole OIDC provider disabled at wiring — refuses",
          "[sso][bootguard][runtime]") {
    auto r = sso_only_runtime_providers_ok(oidc_ready(), false, false);
    REQUIRE_FALSE(r.has_value());
    // Only the provider the operator configured is named in the "but X was disabled"
    // clause (the cause examples further on mention SAML unconditionally).
    CHECK(r.error().find("but OIDC was disabled at startup") != std::string::npos);
    CHECK(r.error().find("but SAML") == std::string::npos);
}

#ifndef _WIN32
TEST_CASE("sso_only_runtime_providers_ok: sole SAML provider disabled at wiring — refuses",
          "[sso][bootguard][runtime]") {
    // e.g. an unreadable / oversized / unloadable IdP certificate leaves saml_provider_ null.
    // Symmetric with the OIDC case above: neither provider gets a weaker guarantee.
    auto r = sso_only_runtime_providers_ok(saml_ready(), false, false);
    REQUIRE_FALSE(r.has_value());
    CHECK(r.error().find("but SAML was disabled at startup") != std::string::npos);
    CHECK(r.error().find("but OIDC") == std::string::npos);
}

TEST_CASE("sso_only_runtime_providers_ok: dual config, one broken — boots; both broken — refuses",
          "[sso][bootguard][runtime]") {
    Config cfg = saml_ready();
    cfg.oidc_issuer = "https://login.example.com/tenant/v2.0";
    cfg.oidc_client_id = "client-abc-123";
    // One working provider is enough: a broken secondary is a log + gauge, not a refusal.
    CHECK(sso_only_runtime_providers_ok(cfg, true, false).has_value());
    CHECK(sso_only_runtime_providers_ok(cfg, false, true).has_value());
    // Both down: refuse and name both.
    auto r = sso_only_runtime_providers_ok(cfg, false, false);
    REQUIRE_FALSE(r.has_value());
    CHECK(r.error().find("but OIDC and SAML were disabled at startup") != std::string::npos);
}
#endif

TEST_CASE("sso_only_runtime_providers_ok: break-glass does not satisfy the check",
          "[sso][bootguard][runtime]") {
    // Break-glass is the recovery for an IdP outage AFTER a successful start, not
    // an SSO provider. Configuring it must change NOTHING: same verdict and the
    // same message as without it (the text mentions break-glass unconditionally,
    // so asserting the word would prove nothing — compare the two results).
    Config without = oidc_ready();
    Config with = oidc_ready();
    with.break_glass_user = "emergency-admin";
    auto a = sso_only_runtime_providers_ok(without, false, false);
    auto b = sso_only_runtime_providers_ok(with, false, false);
    REQUIRE_FALSE(a.has_value());
    REQUIRE_FALSE(b.has_value());
    CHECK(a.error() == b.error());
    // ...and a working provider still passes with break-glass set (it is not a blocker either).
    CHECK(sso_only_runtime_providers_ok(with, true, false).has_value());
}

TEST_CASE("sso_only_runtime_providers_ok: no configured provider at all — generic wording",
          "[sso][bootguard][runtime]") {
    // Unreachable in production (main.cpp's presence guard refuses first) but the
    // helper must still refuse and say something coherent when called directly.
    Config cfg;
    cfg.auth_mode = "sso-only";
    auto r = sso_only_runtime_providers_ok(cfg, false, false);
    REQUIRE_FALSE(r.has_value());
    CHECK(r.error().find("the configured SSO provider") != std::string::npos);
}

TEST_CASE("sso_only_runtime_providers_ok: the refusal states the cause and the safe recovery",
          "[sso][bootguard][runtime]") {
    auto r = sso_only_runtime_providers_ok(oidc_ready(), false, false);
    REQUIRE_FALSE(r.has_value());
    // Points at the log for the cause and warns what the escape hatch re-enables.
    CHECK(r.error().find("logged just before this line") != std::string::npos);
    CHECK(r.error().find("local-password login enabled again") != std::string::npos);
}

// ── Gauge publisher (#4160) ─────────────────────────────────────────────────
// The same function the ServerImpl constructor and the Settings OIDC save call,
// asserted against a standalone registry (the acceptance criterion's "and the
// gauge"). configured=1 with enabled=0 is the "configured but disabled at
// runtime" signal.

namespace {
// A line of the Prometheus exposition: "<name> <value>".
bool has_sample(const std::string& body, const std::string& name, const char* value) {
    return body.find("\n" + name + " " + value + "\n") != std::string::npos ||
           body.rfind(name + " " + value + "\n", 0) == 0;
}
}  // namespace

TEST_CASE("publish_*_provider_gauges: configured and enabled are independent 0/1 gauges",
          "[sso][bootguard][metrics]") {
    yuzu::MetricsRegistry m;
    publish_oidc_provider_gauges(m, /*configured=*/true, /*enabled=*/false);
    publish_saml_provider_gauges(m, /*configured=*/false, /*enabled=*/false);
    std::string body = m.serialize();
    // "configured but disabled at runtime" — the alertable state:
    CHECK(has_sample(body, "yuzu_auth_oidc_provider_configured", "1"));
    CHECK(has_sample(body, "yuzu_auth_oidc_provider_enabled", "0"));
    // "not configured":
    CHECK(has_sample(body, "yuzu_auth_saml_provider_configured", "0"));
    CHECK(has_sample(body, "yuzu_auth_saml_provider_enabled", "0"));

    // Republishing (the Settings save path) overwrites rather than duplicating.
    publish_oidc_provider_gauges(m, true, true);
    body = m.serialize();
    CHECK(has_sample(body, "yuzu_auth_oidc_provider_enabled", "1"));
    CHECK_FALSE(has_sample(body, "yuzu_auth_oidc_provider_enabled", "0"));

    // SAML with the two flags set the OTHER way round, and OIDC unconfigured-but-enabled,
    // so a swapped or constant-valued publisher cannot hide behind (false,false).
    yuzu::MetricsRegistry m2;
    publish_saml_provider_gauges(m2, /*configured=*/true, /*enabled=*/false);
    publish_oidc_provider_gauges(m2, /*configured=*/false, /*enabled=*/true);
    body = m2.serialize();
    CHECK(has_sample(body, "yuzu_auth_saml_provider_configured", "1"));
    CHECK(has_sample(body, "yuzu_auth_saml_provider_enabled", "0"));
    CHECK(has_sample(body, "yuzu_auth_oidc_provider_configured", "0"));
    CHECK(has_sample(body, "yuzu_auth_oidc_provider_enabled", "1"));
    publish_saml_provider_gauges(m2, true, true);
    body = m2.serialize();
    CHECK(has_sample(body, "yuzu_auth_saml_provider_enabled", "1"));
}
