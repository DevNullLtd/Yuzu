# Security review — `--auth-mode=sso-only` covers SAML (SOC 2 CC6.3)

**Date:** 2026-09-08
**Change:** Extend the hardened-mode (`--auth-mode=sso-only`) boot guard so a
SAML-only deployment can disable local-password login. Previously the guard
required OIDC and never consulted SAML, so a SAML-only deployment could not enter
hardened mode.
**Branch:** `feat/auth-saml-sso-only`
**Controls:** SOC 2 **CC6.3** (logical access — disable local-password fallback).
Closes the `docs/auth-architecture.md` "Deferred items" CC6.3 gap and the
`/auth-and-authz` gap-matrix SAML tail (P1 #6).

## What shipped

- **`sso_only_boot_guard_ok(const Config&, std::string& err)`**
  (`server/core/src/sso_boot_guard.{hpp,cpp}`) — the testable core of the
  `sso-only` boot guard, extracted from `main.cpp` (which previously inlined an
  OIDC-only check), mirroring the existing `scim_boot_guard_ok` pattern. Returns
  true when: `auth_mode != "sso-only"`, OR a provider that can actually mint a
  session is configured — **OIDC** (`--oidc-issuer` AND `--oidc-client-id`), or
  **SAML** (all five SP fields AND `https_enabled`, non-Windows). `main.cpp` is
  now a thin wrapper that logs `err` and returns `EXIT_FAILURE`.
- **Shared predicate `saml_config_complete(const Config&)`** — the same 5-field
  presence check `server.cpp`'s SAML wiring uses; `server.cpp` now calls it
  instead of an inlined copy, so the two cannot drift.
- **Boot banner** names the active SSO path(s) (`OIDC`, `SAML`, or `OIDC + SAML`)
  instead of the now-false "only OIDC SSO can mint a session".

## Threat analysis

- **The lockout hole the review caught (HIGH, fixed before implementation).** A
  presence-only SAML term would have let `--auth-mode=sso-only --no-https` with a
  complete SAML config boot successfully — but `server.cpp` leaves the SAML
  provider null under `--no-https` (its Secure browser-binding cookie is dropped
  over plain HTTP, so `/auth/saml/start` 404s), so local-password is disabled
  *and* no SSO path works: **fleet-wide lockout**. `https_enabled` is therefore
  part of the gate, not deferred to runtime — it is a deterministic `Config`
  field, so gating on it satisfies the same "gate on the predicate the provider
  uses to enable itself" rule the OIDC leg follows (#1735 HIGH-1). The guard
  emits an HTTPS-specific error for this case.
- **Windows.** The SAML provider is a compile-time stub on `_WIN32`
  (`is_enabled()` always false, `saml_provider_` never constructed). A complete
  SAML config there can never mint a session, so the SAML term is excluded under
  `#ifndef _WIN32`; a Windows *server* still needs OIDC for `sso-only`. Running
  the server on Windows is out of scope regardless (the managed-endpoint agent is
  unaffected).
- **Presence, not runtime validity (deliberate, mirrors OIDC).** A SAML config
  whose IdP cert or SP signing key is unreadable / oversized / non-RSA passes the
  boot guard and is then disabled **loudly** by `server.cpp`. This matches the
  OIDC leg, whose issuer/JWKS runtime reachability is likewise not gate-checked.
  A deployment that misconfigures the cert this way, with no OIDC fallback, would
  boot with local-password disabled and SAML loudly disabled — recoverable via
  the break-glass account (host-CLI armed) exactly as an OIDC-outage is.
- **No new authentication surface.** The `POST /login` local-password gate and
  the `/auth/saml/start` + `/saml/acs` handlers are unchanged — they key on
  `auth_mode` / provider-enabled state independently and already behaved
  correctly for SAML under `sso-only`. This change only removes the boot-time
  refusal.

## Residual limitations (documented, not defects)

- **No JIT elevation for SAML operators.** A SAML session cannot local-TOTP
  step-up and carries no OIDC `amr` proof, so `POST /api/v1/elevate` is
  unavailable to it. A SAML-only `sso-only` deployment grants admin via the
  group→role mapping (`--saml-admin-group`), not JIT. Pre-existing SAML property,
  surfaced in `docs/auth-architecture.md` and the user manual.
- **No SAML login-page button.** `/login` still shows a password form (always
  401 under `sso-only`); SAML operators use `GET /auth/saml/start`. Pre-existing;
  tracked as a deferred SAML UX item.

## Tests

`tests/unit/server/test_sso_boot_guard.cpp` (new) — the first direct coverage of
the hardened-mode boot gate (previously exercised only by booting a server):
standard-mode always-ok; OIDC complete ok; OIDC issuer-without-client-id fails;
no-provider fails; OIDC + `--no-https` still ok (unchanged OIDC parity);
SAML-only complete + HTTPS ok; SAML-only complete + `--no-https` fails with an
HTTPS-naming error; SAML partial fails; dual OIDC+SAML ok; and a Windows-guarded
case asserting a complete SAML config does **not** satisfy the gate on `_WIN32`.

## Reviewers

Plan adversarially reviewed by the Fable-tier `enterprise-architect` validator
(APPROVE-WITH-CHANGES) — it caught the `--no-https` lockout (HIGH), the Windows
test-build red, and the prose truth-findings, all folded in above before
implementation.
