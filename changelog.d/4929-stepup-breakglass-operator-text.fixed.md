- **Step-up, break-glass and readiness signals now say what the server does.**
  The startup warning for `--mfa-step-up-window-secs=0` said it disabled step-up
  "entirely"; the JIT-elevation endpoints still demand an enrolled caller's proof
  be no older than 300s, and the warning now says so. The break-glass 403's remediation told operators an
  SSO admin could enroll MFA for the break-glass account from Settings, which
  enrollment's self-service model does not allow; it now gives the working
  sequence (restart with `--auth-mode=standard`, sign in as the account, enroll,
  restore `sso-only`), and the recovery runbook documents it in full, including
  TOTP rotation. The OpenAPI spec now documents the step-up `401` on token
  create/revoke, Guaranteed State rule create/update/delete/push and `/elevate`,
  and gives user unlock's step-up failure as `401` (it was listed as `403`); the
  REST reference's step-up endpoint list and the unlock and elevation-eligibility
  error codes now match. `/readyz` reports a dead NVD CVE cache in its non-gating
  `degraded` list. A new `YuzuBreakGlassLogin` alert pages on any
  password-verified break-glass login (a login refused for missing MFA is
  audit-only); `yuzu_auth_break_glass_login_total` is now boot-seeded so the
  alert sees the first use after a restart.
