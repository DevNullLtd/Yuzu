# Adversarial-review synthesis — SAML display-name/email attribute parsing

**TARGET:** `feat/auth-saml-attributes` @ `8531c1e80` — SAML AttributeStatement parsing
(display name + email), XSW-verified session-enrichment, sanitised at parse.
**ANCHORS:** `docs/auth-architecture.md` (SAML sections), `docs/adr/2001-scim-oidc-identity-linkage.md`,
CLAUDE.md standing rules, `docs/agentic-first-principle.md`.
**PANEL:** Codex (empirical, `compiled`+`test-run`) · Kimi-K3 (static-read) · Opus (adjudicator).

## VERDICT: PASS

Both independent reviewers returned **PASS** on Phase 2. The two Phase-1 defects
(C1 HIGH, C2 LOW) are fixed on `8531c1e80` and both were **withdrawn** by their
originator after re-verification. No finding survives cross-examination at MEDIUM
or above. Every residual is LOW and already tracked in follow-up #3688 / #3689.

## Phase-1 blockers — both fixed, both withdrawn

| ID | Sev | Provenance | Status |
|----|-----|-----------|--------|
| **C1** | HIGH | test-run | **WITHDRAWN.** Route test built `SamlRoutesFixture` inside a value-returning lambda called from `CHECK(...)`; on the no-PG leg the fixture ctor's `YUZU_REQUIRE_PG_DB` `SKIP()` threw from inside `CHECK` → `{ nested SKIP() called }` FAILED (exit 42), breaking the supported no-Postgres Linux SAML leg (policy floor). Fixed by hoisting the fixture to test-body scope (line 1425). Codex re-ran `env -u YUZU_TEST_POSTGRES_DSN ... '[saml]'` → exit 0, 85 passed / 66 skipped, 725/725 assertions. |
| **C2** | LOW | static-read | **WITHDRAWN.** Windows unsupported-feature predicate in `server.cpp` didn't enumerate the two new SAML flags → silent config-drift (no auth weakening; `saml_provider_` stays null on Windows). Fixed by adding `saml_name_attribute`/`saml_email_attribute` to the predicate. |

## Consolidated residual findings — all LOW, all tracked

| ID | Sev | Found-by | Anchor/judgment | Disposition |
|----|-----|----------|-----------------|-------------|
| **C3 = K1** | LOW (judgment) | both, independently | judgment | Sanitiser strips C0+DEL but not UTF-8 U+0085/U+2028/U+2029 (and C1 block); a Unicode-aware log viewer could split a line. **Does NOT violate the stated C0+DEL contract** — residual hardening. → **#3688** (cross-SSO control-char + bidi + line-separator strip; OIDC has the identical posture, so a SAML-only fix would create OIDC/SAML inconsistency). |
| **K5** | LOW (hi) | Kimi | judgment | The raw NameID flows unsanitised to the same two log sinks as the sanitised attributes (asymmetry). Same class as C3/K1, same OIDC-parity reasoning. → **#3688**. |
| **K2** | LOW (lo) | Kimi | judgment | Email is PII in operational logs. OIDC-consistent posture (email/display already logged there). Log-PII posture decision → **#3688**. |
| **K3** | LOW (lo) | Kimi | judgment | Hypothetical XSS if a downstream UI renders `display_name` unescaped. Adjudicated: dashboard consumers use `.textContent`/JSON (verified in Step 0); Codex's consumer sweep of `rest_api_v1.cpp`+UI raised no escaping finding. No live sink. Stays `not-verified` LOW. |
| **K4** | — | Kimi | — | **WITHDRAWN (falsified).** Kimi's "no tests visible" hedge resolved against it: Codex's run proves parser/XSW/sanitiser tests exist and pass (43 assertions in the sanitise case). Correct empirical-over-static weighting. |
| **K6** | LOW (hi) | Kimi | judgment | Whitespace-only post-sanitise value passes the non-empty gate and shadows a later real value. Adjudicated no-op: `get_text` already trims, and the derivation is name→email→NameID so a blank display still falls through to NameID. → noted, not tracked (behaviourally inert). |

## Adjudicated disagreements

None of substance. The one asymmetry the panel split on — Codex's Phase-1 silence
on K4/test-adequacy vs Kimi's static "tests may not exist" — was resolved
**empirically** in Codex's favour on Phase 2 (the tests exist and pass), and Kimi
adopted the empirical result. This is the static-vs-empirical weighting working as
designed: Codex carried the compile/test evidence, Kimi carried diverse static
breadth (the Unicode-separator residual C3/K1 that Codex's Phase-1 missed and then
independently confirmed on Phase 2).

## Coverage

- **Deep (both):** XSW parity (attributes read only from the verified assertion node),
  identity/authz/SCIM isolation (NameID-only via `saml_principal_id`; admin only from
  the group attribute), sanitiser byte-level (C0+DEL strip + 256-byte UTF-8-boundary
  clamp), correctness of the name→email→NameID derivation, cross-component consistency
  with OIDC.
- **Empirical (Codex):** `meson compile` PASS; `[saml]` suite PASS on the no-PG leg
  (85 pass / 66 skip, 725/725 assertions); Windows-detector and multibyte-clamp
  edits confirmed present.
- **Adopted-by-Kimi:** test adequacy + Windows cross-platform (both `not-verified`
  statically — the test file and `_WIN32` detector were outside Kimi's CONTEXT).
- **Skimmed (concur):** resource/concurrency (no new owning handles/threads; new
  strings value-owned; `create_saml_session` mutation under `mu_`), macOS (shared
  non-Windows path).

## What each reviewer ran

- **Codex:** `meson compile -C build-linux tests/yuzu_server_tests` (PASS);
  `env -u YUZU_TEST_POSTGRES_DSN ./build-linux/tests/yuzu_server_tests '[saml]'`
  (exit 0). No PG DSN available → PG-backed sections skipped. No Windows/macOS host.
  CI not re-queried (network restricted) — unobserved, not claimed.
- **Kimi-K3:** static-only over the injected CONTEXT bundle (diff + changed
  functions + neighbours + anchor excerpts). No compile/test.
- **Opus (me):** assembled context, enforced both barriers, adjudicated K3/K6 to the
  code, verified the C1/C2 fixes are on `8531c1e80`, confirmed C3/K1/K5/K2 are
  captured in #3688.

## Gate outcome

**PASS after C1/C2/K4 resolution.** Proceed to Hermes (the operator chose
"Full stack + Hermes"), then rebase/retest/push on the standing "Push + open PR now".
