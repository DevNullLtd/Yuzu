- **Breaking: approving or rejecting an approval request now requires an enrolled MFA factor with a fresh proof, in every `--mfa-enforcement` mode (#6079).**

  **Action required before upgrading** (the full checklist is in `docs/user-manual/upgrading.md`):

  - On a default install every approver is refused until it enrols itself; another administrator cannot enrol it.
  - Administrators enrol in Settings, Security and sign-in, Two-factor sign-in.
  - Non-admin approvers need the runbook path, `docs/ops-runbooks/auth-db-recovery.md` "Enrolling a non-admin approver".
  - A SAML-only deployment has no approver path (#6098).
  - Mixed-version running is unsupported and there is no rollback; see the upgrade notes.

  `POST /api/approvals/{id}/approve`, `POST /api/approvals/{id}/reject` and the dashboard Approvals page now run the central step-up check first and then a stricter approver rule of their own, because the central check passes an account that has no factor. A local account must have an enrolled TOTP factor and a proof no older than the approver window that belongs to the factor enrolled now (the proof records the account's factor generation, so disabling MFA and enrolling again makes earlier proofs stop counting). An OIDC session qualifies when the identity provider issued an ID token with an MFA-method `amr` within the window; no second factor is presented again at approval time. A SAML session is refused (#4935). The approver window is `min(--mfa-step-up-window-secs, 300)` seconds, and 300 when that setting is `0` or negative, measured on the database clock with no suspend or skew allowance, so `--mfa-step-up-window-secs=0` no longer lowers approval assurance and no longer admits a SAML approver. Break-glass accounts get no exemption and the reviewer must still differ from the submitter. The `attempted` and `success` audit rows of a decision carry `detail` `approver_assurance:enrolled_fresh_mfa` as the cutover marker.

  A refused caller gets `403` with message `approver_assurance_required:<reason>`. `mfa_not_enrolled` is typed at every window; the other reasons are typed only in some configurations, because with the step-up window above `0` the central check answers first with its generic `401` or `403`. The full matrix is in `docs/user-manual/authentication.md`, "Approver MFA requirement".

- **Approver refusal answers and audit detail (#6079).**

  When the approver rule's own read fails (an unreadable stored session proof, or an MFA-store fault at its own read) the answer is `503` with `retry_after_ms` 5000, counted as `yuzu_auth_secret_unavailable_total{route="approval"}`. With step-up on, an unreadable local MFA store is answered first by the central check: `503` with no `retry_after_ms` key, counted as `route="mfa_stepup"` and `yuzu_auth_mfa_step_up_gate_total{outcome="unavailable"}`.

  An OIDC approver whose stored MFA proof is dated after the database clock (the replica that took the sign-in ran ahead of the database clock) is refused `503` with `retry_after_ms` null and audit `detail` `approver_assurance:mfa_proof_clock_skew`, and is not counted in `route="approval"`; it needs a clock-synchronisation fix, not a retry. It is reached only when the central check does not answer first (default optional enforcement, `admin-only` for a non-administrator, or step-up window `0`); afterwards the approver gets `403` `mfa_proof_missing`, whose remediation always ends by asking the administrator to check clock synchronisation.

  A path id that is empty, longer than 128 characters or holds anything other than letters, digits, `_` and `-` is refused before the store is asked, with `400`, an A4 envelope (message `approval not found`) and one `denied` row (`target_id=invalid-id`, `detail=invalid_approval_id`). An unknown id that passes that check still gets the store's older `{"error":"..."}` string shape, so a client that parses the body should handle both.

  The `user=` value in the `detail` of every `mfa.step_up.required` audit row is now neutralised: a space, `=`, `,`, DEL or control byte in the account name is written as `_`, so a SIEM rule that matches that field must match the neutralised form.

  The dashboard approve dialog and Approvals tab now show the A4 message and remediation of a `503` together to the approver instead of a generic message.

