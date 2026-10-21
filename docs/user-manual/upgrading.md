# Upgrading Yuzu

This guide covers upgrading Yuzu components (server, agent, gateway) between versions.

## ⚠️ Breaking: cookie-session writes require a same-site Origin or Referer

**Before you upgrade.** Do these on the version you are running now:

1. If a reverse proxy fronts the dashboard, check that it forwards the client's `Host` unchanged, port included. nginx rewrites `Host` by default (it sends `$proxy_host`), so add `proxy_set_header Host $http_host;` in every `location` that proxies to Yuzu, or at `server` level. `$host` drops the port, so use `$http_host` unless the public port is 80 or 443. Behind a TLS-terminating proxy, also declare the public origin with its scheme (for example `--csrf-trusted-origin https://yuzu.example.com`) even when `Host` is forwarded: the server cannot see the public scheme, and the scheme-qualified entry makes it refuse a plain-`http://` `Origin` for that host. If the proxy cannot forward `Host`, set `--csrf-trusted-origin https://<public-origin>` (or the environment variable `YUZU_CSRF_TRUSTED_ORIGIN`) on **every** server replica first, restart, and confirm the start-up line described under "Confirming it took" in [Server Administration](server-admin.md#vnext--behind-a-reverse-proxy-declare-your-external-origin-or-csrf-gated-dashboard-actions-keep-failing-2537).
2. Create at least one API token for your automation before upgrading. Creating a token from the dashboard is itself a cookie-session write, so it is refused on a misconfigured proxy after the upgrade.
3. A script that reuses a login cookie jar should switch to the token.

**Symptom and recovery.** On a deployment that skipped step 1, every dashboard write answers `403` `cross-site request refused`; sign-in and ordinary reads still work, API tokens cannot be created, and the step-up elevation request is refused. The check cannot be disabled: the remedies are the flag, an API token or rolling back. Recovery is to restart with the flag or environment variable, or to reach the server directly (for example an SSH tunnel to the web port, so `Host` matches `Origin`), sign in and create a token. A script that reaches the server directly must send an `Origin` naming the address it connects to (for example `http://localhost:8080`, or `https://localhost:8443` when the server terminates TLS itself, where an `http://` origin is refused). Direct access needs a local sign-in: a deployment that offers only OIDC or SAML sign-in redirects to the public URL, so for those only restarting with the flag works. There is no reload: the value is read at start. Every replica needs the same value, or the same page flaps between `200` and `403` depending on which replica answers. An `Origin: null` header, which some browser and proxy configurations send, cannot be fixed by the flag; do not set `Referrer-Policy: no-referrer` at the proxy (it removes the `Referer` fallback, and the Fetch standard makes browsers serialise the `Origin` of a non-CORS form submission as `null` under that policy; script-driven requests are unaffected), and the remedy is to remove it or roll back. `/livez` and `/readyz` stay green throughout, so a probe does not detect this. The upgrade makes no schema change, so downgrading is safe.

**What changed.** Every request other than `GET`, `HEAD` or `OPTIONS` that is authorised by a **session cookie** must carry an `Origin` or `Referer` header naming this site (or an entry from `--csrf-trusted-origin`). Otherwise it answers `403` `cross-site request refused` (the standard error envelope, with a `remediation`) and is audited as `csrf.denied`. One check, applied centrally, decides this after authentication and before step-up evaluation, challenge emission and route-handler effects, and before the request body is parsed; a client that sends `Expect: 100-continue` has already been told to send the body, and a large upload may still be in flight when the `403` arrives. A request that presents a valid session cookie is treated as a cookie-session request even if it also carries a token. A request authenticated only by an API, MCP or engine token is not subject to this check, and neither is a request answered before a session is resolved. The per-route checks described elsewhere in this guide stay in place as defence in depth; a few dashboard-panel routes keep a copy of their own that is not token-exempt, so a token caller of one of those can still be refused by it.

**Guarded reads.** The same rule also covers cookie-session requests that dispatch work, persist state or force a refresh of server state, whichever method they use (the guarded reads). The exact path, never a query flag, selects the gate. The mechanism for them is the browser's fetch metadata, and a `Sec-Fetch-Site` header that is present decides alone: exactly one header with value `same-origin` or `none` is admitted, any other value (or a repeated `Sec-Fetch-Site` header) is refused with `origin_mismatch`, and `Origin` and `Referer` are not consulted. Only when `Sec-Fetch-Site` is absent does the `Origin` or `Referer` rule above apply. Browsers send `Sec-Fetch-*` headers only to potentially trustworthy origins (HTTPS and loopback), and Safari before 16.4 sends none, so on a plain-HTTP deployment at a non-loopback address these requests depend on the `Origin`/`Referer` rule; a same-origin `GET` carries no `Origin`, so it depends on `Referer`, which the server's default `Referrer-Policy` (`strict-origin-when-cross-origin`) supplies. A proxy or page policy of `no-referrer` would break those dashboard panels on such a deployment; a TLS-terminating proxy is fine, because the browser talks to the proxy over HTTPS. These requests are audited as `csrf.denied` with a `target_id` such as `GET /path`. Token callers are not gated.

**Who is affected.** A script or tool that signs in with a cookie and writes without an `Origin` or `Referer` header now gets `403`. A deployment behind a reverse proxy that rewrites `Host` and has no `--csrf-trusted-origin` entry has every cookie-session write refused until the flag is set. At start-up the server prints one line to standard output: the number of origins accepted and their values when at least one is accepted, otherwise the rule and a note that none was accepted (it is not written to `--log-file`, and `--log-level` does not hide it). The first refusal of each kind logs a warning naming the flag. The dashboard and other browsers send these headers on every write and need no change. A script or tool that sends the guarded reads (cookie-session requests that dispatch work, persist state or force a refresh of server state) with a login cookie and no `Sec-Fetch-Site` header must now send a same-site `Origin` or `Referer`; one that sends `Sec-Fetch-Site` must send it once with value `same-origin` or `none`. Otherwise it gets `403`. The audit row for such a refusal still carries the fixed detail text "browser write refused". Browsers need no change. On most dashboard pages a refused write shows no error message (the page does not swap the `403` response in), so a proxy misconfiguration can look like buttons that do nothing; check the audit log and `yuzu_server_csrf_denied_total`.

**How to fix.** Send `Origin` matching the console origin (for example `-H "Origin: https://yuzu.example.com"`), or `Referer` for an endpoint that validates `Origin` against its own allowlist (see [MCP](mcp.md)), or use an API token. Behind a reverse proxy, declare the public origin with `--csrf-trusted-origin`, including the scheme (for example `https://yuzu.example.com`); this is required if the proxy rewrites `Host`, and with a scheme it also makes the server refuse a plain-`http://` `Origin` for that host. A server that terminates TLS itself needs no declaration: it requires an `https://` `Origin` or `Referer`. For the guarded reads, either send no `Sec-Fetch-Site` header and a same-site `Origin` or `Referer`, or send `Sec-Fetch-Site` once with value `same-origin` or `none` (a `Sec-Fetch-Site` header that is present decides alone, so a script that sets it to any other value, or sets it twice, is refused even with a good `Origin`); or authenticate with an API token. Do not configure the proxy to inject or rewrite `Origin` or `Referer`, which would turn the control off for that deployment. No data migration is required.

**What to check.** Since this release, a `csrf.denied` row for a cookie-session caller has `result` `denied`, `target_id` set to the sanitised request method and path (for example `POST /path`; the request path is truncated at 200 bytes) and a `detail` of fixed text followed by `reason=<token>`. Rows keyed on the earlier per-route `target_id` values or on `result` `error` now appear only for token callers of the dashboard-panel routes that keep their own non-token-exempt copy, so a SIEM rule keyed on those values goes quiet for cookie callers: re-key it on `action` `csrf.denied` (and `result` `denied`), and treat the date of this release as the boundary in exported evidence. The counter `yuzu_server_csrf_denied_total{path_class,reason}` records every refusal (`reason` is `no_origin_no_referer`, `origin_mismatch`, `referer_mismatch` or `gate_error`) and the shipped `yuzu-web-writes` alert rules watch it ([Metrics](metrics.md)); a rise after the upgrade is usually a script without the header or a proxy without the flag.

## Behaviour change: privileged REST routes refuse cross-site cookie writes

**What changed.** A call to a privileged REST write route (the routes whose reference entry carries a "Cross-site writes" note in the [REST API](rest-api.md) guide) authorised by a **session cookie** must carry an `Origin` or `Referer` header naming this site (or an entry from `--csrf-trusted-origin`). Otherwise it answers `403` `cross-site request refused` and is audited as `csrf.denied`. The central same-site check (see the section above) answers first, after authentication and before authorization; each of these routes keeps its own copy after its authorization gates and MFA step-up as defence in depth, and before the request body is read. API, MCP and engine token callers are not affected by these routes.

**Who is affected.** A script or tool that signs in with a cookie and calls one of these routes without an `Origin` or `Referer` header now gets `403`. No dashboard page calls these routes.

**How to fix.** Call the route with an API token, or send an `Origin` header matching the dashboard origin (for example `-H "Origin: https://yuzu.example.com"`). Behind a reverse proxy that rewrites `Host`, declare the public address with `--csrf-trusted-origin`. No configuration or data migration is required.

## ⚠️ Breaking: approving or rejecting a request now needs an interactive session and MFA step-up; MCP cannot approve (#6061)

**What changed.** Approve and reject (`POST /api/approvals/{id}/approve`, `POST /api/approvals/{id}/reject`,
the dashboard Approvals page, and the MCP tools `approve_request` / `reject_request`) now require all of:
an interactive cookie session (local or OIDC), a fresh MFA step-up (with the pass-through described below), a human
principal and not an engine principal. The existing rule that the reviewer cannot be the submitter is unchanged.

- **API-token and MCP-token sessions are refused** with a typed `403` (A4 error envelope).
- **MCP can no longer approve or reject.** The MCP transport is not an approval surface (it
  runs no MFA step-up), so `approve_request` and `reject_request` always return a typed refusal, whatever
  credential the caller used. This is an exception recorded in
  ADR-1005's exception ledger (entry 2026-10-18: "human review is a human-session act"). The tools stay registered, and listing pending
  approvals through MCP is unchanged. Their tier/permission mapping is `Approval:Approve` (it was
  mapped as `Approval:Write`, #3151).
- **SAML users cannot approve while MFA step-up is on.** SAML sessions can never pass step-up (#4935). A
  deployment whose approvers all sign in through SAML therefore has no working approver path until they are given
  an OIDC provider or a local account, or step-up is turned off fleet-wide with `--mfa-step-up-window-secs=0`
  (under `--auth-mode=sso-only` the only local sign-in left is the break-glass account, which is not a substitute).
  This is a known limitation, tracked in #6098.
- **"Fresh MFA step-up" is not a guarantee of a second factor.** The step-up gate can only ask for a factor the
  account has, so it passes without a second factor for a local account with no enrolled factor (in every
  `--mfa-enforcement` mode; `required`, and `admin-only` for admins, force enrolment at login, so in practice any
  account under `optional` and a non-admin under `admin-only`), for an OIDC session whose identity provider
  asserted no `amr` proof **unless `--mfa-enforcement=required`** (under `admin-only` it still passes for a
  non-admin role), and for any session when `--mfa-step-up-window-secs=0`. `--mfa-enforcement=required` closes the
  OIDC case only if your identity provider asserts an MFA-method `amr` for approvers: an OIDC session without one
  gets `401` and loops through re-sign-in at every step-up endpoint, not only approval, which locks those operators
  out of all of them. Check `amr` before enabling `required`; the way back is restarting the server in
  `optional` temporarily (it weakens MFA fleet-wide, so restore your intended enforcement afterwards), not just any non-`required` mode, because an `amr`-less OIDC admin is still gated under `admin-only` (see
  [MFA on SSO sessions](authentication.md#mfa-on-sso-sessions-pr-3) and the
  [recovery runbook](../ops-runbooks/auth-db-recovery.md#locked-out-by-mfa-enforcement-misconfiguration)). (SAML sessions are refused at step-up gates in every mode, independent of `required`.) Requiring that the approver holds an enrolled factor
  in every mode is tracked in #6079.
- **A same-site `Origin` (or `Referer`) is now required.** A browser or script `POST` to
  `/api/approvals/{id}/approve` or `/reject` that authenticates with a session cookie and carries no `Origin` or
  `Referer` naming this site now gets `403` (audited as `csrf.denied`, before any step-up is spent). A script that
  signs in with `curl -b` must send `-H "Origin: <the server's own base URL>"`. A deployment behind a
  TLS-terminating or Host-rewriting reverse proxy must declare the public address with `--csrf-trusted-origin`, as
  for the sibling cookie-write routes described further down this page (for example the hardware-sync and
  `PUT /api/config/{key}` notes) and in [Server Administration](server-admin.md), or the dashboard's Approve and Reject buttons are refused. Token callers
  are not subject to this check (they are refused as non-interactive sessions instead). The dashboard dialog shows
  every `403` as "You do not have permission to decide approvals", so a missing `Origin` looks like a permission
  problem there; see "Who can approve" in `instructions.md` for the causes.
- **A degraded session read fails closed.** The route answers `503` and the request stays pending; it no
  longer records the reviewer `unknown` (#4128).
- **The attempt is audited first.** If the audit row cannot be written, approve and reject return `503`
  and change nothing (#5823).
- **Expiry is enforced at consume.** An approved request not used within 7 days of its review is refused
  when it is consumed, using database time, even if no new request has been submitted since. The `status` shown on
  the Approvals page and returned by the list routes (`GET /api/approvals`, `GET /api/v1/approvals`, MCP
  `list_pending_approvals`) is only rewritten to `expired` by the next accepted approval submission, so an aged approved ticket
  keeps showing `approved` until then even though consume and `ScheduleRunner` already refuse it (tracked in #6098).

**Who this affects.** Any automation that approved or rejected over MCP or with an API token. It will now
fail. A supervised-tier agentic worker still requests approval and recalls with the `approval_id`, but a
person must approve in the dashboard or over REST on a signed-in session. SAML-only approvers must sign
in with a local account or OIDC. Scripts that approve with a session cookie must complete the step-up
(`POST /login/mfa/stepup`) when they receive `401` with `meta.mfa_step_up_required`.

**If you set `--mfa-step-up-window-secs=0`,** approval loses its MFA requirement and is protected by the
interactive-session rule only. Review every `approval.approve` audit row with `result=success` if you run
that way, and check every `attempted` row that has no outcome row (compare counts per `target_id`). Each
decision also writes a `result=attempted` row first, so do not count both, and a decision whose outcome row
failed to write leaves only the `attempted` row (see [Audit Log](audit-log.md)).

**Find affected automation before you upgrade.** Nothing is listed for you, so search the audit log for
callers that approved or rejected without a signed-in browser session.

- **Over MCP.** Audit rows with action `mcp.approve_request` or `mcp.reject_request` are MCP approvals. The
  REST audit API can find them: `GET /api/v1/audit?action=mcp.approve_request` (and `mcp.reject_request`);
  `principal` names the account that made the call.
- **Over REST with a token.** The audit row for a decision made with a bearer token carries
  `principal_class = 'agent'`; a signed-in browser session carries `'human'`. `GET /api/v1/audit` returns
  neither `principal_class` nor `session_id`, so the REST audit API cannot separate the two. Query the
  audit store (PostgreSQL) directly:

  ```sql
  SELECT timestamp, principal, action, result, target_id, source_ip, user_agent
  FROM audit_store.audit_events
  WHERE action IN ('mcp.approve_request', 'mcp.reject_request')
     OR (action IN ('approval.approve', 'approval.reject') AND principal_class <> 'human')
  ORDER BY timestamp DESC;
  ```

  A row with an empty `principal_class` is one the server could not attribute to a token or a session; read
  `user_agent` and `source_ip` for those.

The search only sees what the audit retention window still holds, so an empty result is not proof that nothing
approves by token. Before upgrading, also check which service accounts and API tokens hold `Approval:Approve`
and move each approval step to a person on a signed-in session. No audit query lists a token or service account
that holds `Approval:Approve` but has never approved: after this change it is refused anyway, so the check is
about finding automation to move, not about finding exposure. To list what is granted, read the RBAC grants
(`GET /api/v1/rbac/roles/assignments`, or the Access Reviews export `GET /api/v1/access-reviews/export`; both
need `AccessReview:Read`) and match each principal's roles against the roles that carry `Approval:Approve`.
`GET /api/v1/tokens` lists only the calling user's own tokens, so check each token owner's grants.

**What that search cannot see.** The audit query finds token and MCP approvers only. The approvers most likely
to hit the new behaviour are human accounts, which carry `principal_class = 'human'` and so look the same before
and after the upgrade: SAML users (refused at step-up), OIDC users whose identity provider asserts no MFA-method
`amr` (refused with a `401` re-sign-in loop under `--mfa-enforcement=required`, and also under `admin-only` for an
admin, and passed through otherwise), and local accounts with no enrolled factor (passed through without a second factor). To
list the SAML and `amr`-less OIDC operators who have signed in, query the login rows in the audit store (the
retention window applies):

```sql
SELECT principal, action, to_timestamp(max(timestamp)) AS last_login
FROM audit_store.audit_events
WHERE action = 'auth.saml_login'
   OR (action = 'auth.oidc_login' AND detail LIKE '%amr_mfa_asserted=false%')
GROUP BY principal, action
ORDER BY last_login DESC;
```

`timestamp` is epoch seconds, hence `to_timestamp`. That lists who signed in by those routes, not who holds
`Approval:Approve`; compare it with the role assignments by hand. For an OIDC row the `detail` column carries the
display name and e-mail (personal data), which helps match a principal to a person. To list the local accounts
that have no enrolled MFA factor (read-only; SSO identities are rows with another `identity_source`), query the
`auth` schema:

```sql
SELECT username, role, last_login_at
FROM auth.users
WHERE is_active
  AND identity_source = 'local'
  AND mfa_enrolled_at IS NULL
ORDER BY username;
```

`role` is the account's legacy role column, not its RBAC grants, so compare the result with who holds
`Approval:Approve`. An account listed here passes the step-up without a second factor.

**After upgrading, verify approvals on a test request.** Use a test device and a harmless, read-only
instruction, and do not skip the safety notes in step 1: an execute call that is not held for approval really
dispatches.

1. Create a pending test request. Pick an instruction definition whose `approval_mode` is `always` (it needs a
   ticket whoever submits it) and that only reads state, such as a status or inventory query. No shipped `always` definition is read-only
   (all are mutating `server.*` actions), so with one of those the `202` `pending_approval` before dispatch is the
   safety property, and anything else is a finding. Do not use a
   `role-gated` definition from an administrator account: under `role-gated` an administrator, including one with
   an active JIT elevation, gets no ticket and the instruction is dispatched. As a signed-in dashboard session,
   or any session you can send a same-site `Origin` with, call the execute route with a JSON object body that names
   ONE test device explicitly:

   ```bash
   curl -b cookies.txt -X POST "https://yuzu.example.com/api/instructions/<definition-id>/execute" \
        -H "Origin: https://yuzu.example.com" -H "Content-Type: application/json" \
        -d '{"agent_ids": ["<test-device-agent-id>"]}'
   ```

   Never omit both `agent_ids` and `scope` on this call: an omitted target is the whole fleet, and only
   destructive and forensic actions refuse it. The body must be a JSON object (a bodiless `POST` answers `400`
   "invalid request body"; `{}` is the minimum), and a session-cookie `POST` without a same-site `Origin` is refused
   with `403` and a `csrf.denied` row. **Expect `202` with `"status":"pending_approval"` and an `approval_id`
   before you go on.** Only a `200` (the instruction was dispatched) means it ran, so stop, treat it as a finding,
   and check what was dispatched; a `400`, `403`, `404` or `503` means nothing was dispatched, so fix the cause and
   retry. A `500` with message `dispatch failed` may already have queued the command, so check the executions
   list before retrying. **You need two distinct accounts:** the
   submitter cannot approve their own request (that attempt answers `400` and leaves an `attempted` and a `denied`
   row), so approve it as a different human account that holds `Approval:Approve`.
   Approving a ticket created this way does not run the instruction: an instruction-origin ticket has no
   redemption path yet, so the approval is recorded and nothing is dispatched (tracked in #6064). The test proves
   the approval gate, not execution.
2. As that human approver on a signed-in browser session, approve the pending test request on the Approvals page.
   Expect the step-up prompt if the proof is older than `--mfa-step-up-window-secs`, then success. The audit store
   should show an `approval.approve` row with `result=attempted` followed by one with `result=success`, and the
   `success` row should carry `principal_class = 'human'`. If you script this step with a session cookie, send an
   `Origin` header naming the server (for example `-H "Origin: https://yuzu.example.com"`), or the `POST` is
   refused with `403` before anything is recorded other than a `csrf.denied` row.
3. With an API token that holds `Approval:Approve`, send `POST /api/approvals/{id}/approve` for a pending request (create a second test request if step 2 already decided the first).
   Expect `403` with message `approver_assurance_required:non_interactive_session`, and one `approval.approve`
   row with `result=denied` and `detail=approver_assurance:non_interactive_session`. The same attempt through MCP
   `approve_request` returns `-32003` with the same message. (A token without `Approval:Approve` gets the plain
   permission `403` first, so it does not prove the new check. Over MCP, an operator-tier or readonly-tier token is
   refused earlier by the tier check with `-32004`; use a supervised-tier or untiered token for this step.)
4. Repeat step 2 with one account of each kind you run: a SAML user (expect `403` "MFA step-up is not available
   for SAML sessions in this release"), an OIDC user your identity provider does not send an MFA `amr` for (what
   you see depends on `--mfa-enforcement`, as above), and a local account with no enrolled factor (it succeeds
   without a prompt for a second factor, which is the documented limit tracked in #6079). Each repeat needs its
   own pending test request, submitted by someone other than the account being tried, and a decided request
   cannot be decided again.
5. Clean up. Reject every test request that is still pending, from the dashboard Approvals page or with
   `POST /api/approvals/{id}/reject` (same gates as approve: a human session with a fresh step-up, a same-site
   `Origin`, and not the submitter). A ticket that is already `approved` cannot be rejected; it stays listed as
   `approved`, is refused at use 7 days after its review, flips to `expired` on the first accepted approval submission
   after that (#6098), is never deleted, and, for an instruction-origin ticket, dispatches nothing. Record the
   ids of the approved test tickets in your change record so nobody mistakes them for a real decision later.

**Rolling back, or running mixed versions.** This change adds no schema, so a rollback starts cleanly. What
changes is which checks run.

- A replica or a rolled-back binary that predates this change still accepts bearer and MCP approvals, and does
  not check an approved ticket's age when it is consumed or when `ScheduleRunner` fires it. While any such
  replica serves traffic, the assurance is only as strong as that replica; drain it, or send approval traffic
  to upgraded replicas only.
- An older binary does not write the `result=attempted` row, and does not read it. Rows written by the new
  binary stay in the audit store and are ignored by the old one; a `denied` row with
  `detail=approver_assurance:<reason>` simply stops appearing.
- A ticket approved by an older replica carries a `reviewed_at` stamped from that replica's own clock. The new
  binaries judge it against database time, so a replica whose clock runs more than 5 minutes ahead of the
  database produces a ticket the new binaries treat as not yet live (a recall over MCP answers
  `approval expired (past its 7-day lifetime)`, although the ticket is in fact ahead of the clock), and a replica
  running behind shortens the ticket's life by the same amount. Once the next accepted approval submission on any
  replica has run, such a ticket is `expired` for good, with only an info log line as a trace, and correcting the
  clock does not bring it back, so request approval again. Until that submission has run nothing has been
  written, so correcting the clock first makes the ticket live again: if the query in `docs/clock-guarded-retention.md` finds
  held-back tickets, fix the clock before anyone submits an approval request. (A submission refused because the pending queue is full
  rolls its sweeps back, so the ticket stays `approved` and unusable until a later submission is accepted.) A
  query that lists approved tickets ahead of the database clock (until that sweep runs) is in `docs/clock-guarded-retention.md`, "ApprovalManager ticket liveness". The same applies to a
  database host whose own clock is stepped backwards by more than 5 minutes: an approved, unused ticket whose review
  time is more than 5 minutes ahead of the new database time (roughly, one reviewed within the last
  (step size minus 5 minutes) before the step) is expired permanently once an accepted submission has swept it
  (until then correcting the clock restores it), and older approved tickets stay live
  (observability tracked in #6098).
- Submission time (`submitted_at`) and the schedule's own run stamps still come from the clock of the server that
  wrote them, not from the database. Keep every server NTP-synchronised. When the server that submitted an approval
  and the one that advances a recurring schedule disagree about the time (a leader change under clock skew, or a clock
  step), an approved ticket can be used for an extra occurrence or be ignored and requested again, and a submitter
  clock far from the database's lengthens or shortens how long its pending requests live. Tracked in #6096.
- Tickets already approved when you upgrade keep their original `reviewed_at`; the seven days are counted
  from it.

## Behaviour change: plugin-enablement tables and the continuity anchor (`plugin_config_store` schema v3, ADR-3006)

The `plugin_config_store` schema moves to v3. It adds the tables of the plugin-enablement store (`enablement_rules`, `enablement_endpoints`, `enablement_meta`) and records a new store id. Nothing flips on upgrade: there is no operator surface yet and nothing issues desired state, so no endpoint's behaviour changes.

- **What you will see.** `/readyz` gains an `enablement` object and `/health` an `enablement_regressed` flag; neither gates readiness. On the first boot after the upgrade the server writes `enablement-anchor` beside its data and reports `anchor_unwitnessed_at_boot: true` once. That is expected and needs no action.
- **Rollback is safe.** v3 only adds tables, and an older server starts on it without complaint (there is no schema-ahead guard) and ignores them.
- **Rolling upgrade.** No behaviour change: a replica on the older release ignores the new tables.
- **Retrying a failed upgrade.** The v3 migration seeds a new store id, and the server writes `enablement-anchor` naming it. If you then restore the pre-upgrade dump and upgrade again, the new store id no longer matches the surviving anchor, and the server logs one warning naming the old and new store id. While nothing has been issued (the anchor's counter and the store's counter are both `0`) that is reported as unwitnessed (`anchor_unwitnessed_at_boot: true` once), the server rewrites the anchor with the current store id, and no regression is declared; the same applies to a fresh database with a kept data directory. If the anchor's counter or the store's counter is above `0`, the server starts with enablement declared regressed (reason `store_id_mismatch`, alert `YuzuEnablementRegressed`); before retrying, remove `enablement-anchor` from the data directory or restore it from the same backup point as the dump. If a regression was already declared, the exit is in [Enablement continuity anchor](server-admin.md#enablement-continuity-anchor).
- **Backups.** The tables ride the existing dump. The anchor file is outside it: keep `enablement-anchor` with the data directory. `scripts/yuzu-backup.sh` and `scripts/yuzu-restore.sh` now copy it.
- **Alerts.** The `yuzu-enablement` group in `docs/prometheus/yuzu-alerts.yml` ships with this change. Until the later change that issues desired state, only `YuzuEnablementRegressed` and `YuzuEnablementAnchorWriteFailing` can fire.

## Behaviour change: the macOS agent package installs transactionally and can refuse

This applies to every macOS `.pkg`, including the release package.

**What changed.**

- The installer stages the new agent beside the running one and validates it.
  The running agent is stopped only after that succeeds. If a running agent was
  replaced and the new one does not stay running, the previous version is
  restored and restarted.
- The installer now **refuses** in these cases, before anything is stopped or
  changed, and says which one applies:
  - `/usr/local`, `/usr/local/lib` or `/usr/local/lib/yuzu`, or `/usr/local/bin`
    for the loose-binary package, is not root-owned or is group- or
    world-writable. That is typical of Macs whose Homebrew lives in
    `/usr/local`: Intel Macs, and Apple silicon Macs running an Intel or
    migrated Homebrew.
  - An agent binary, rollback file or plugin (at any depth) in those directories
    is a symlink, or another account could have written it, including through
    an access control list. The installer lists each entry.
  - `/etc/yuzu-agent` or `/etc/yuzu-agent/certs` is not root-owned, or is group-
    or world-writable.
  - `/Library/Application Support/Yuzu` or `/Library/Logs/Yuzu`, or anything
    in them, is not root-owned, is group- or world-writable, or has an access
    control list that lets another account write to it; or an entry in them is
    a symlink, a special file or a hard-linked file. The agent runs as root and
    opens files there by name. A Mac where `scripts/install-agent-user.sh` gave
    them to `_yuzu` needs them returned to root first. The refusal lists each
    entry; inspect and fix them one at a time, and never `chown -R`, which would
    make a planted symlink look root-owned (see the packaging README).
  - `/var/db/yuzu-agent`, or a recovery snapshot in it, has an access control
    list. The installer never sets one, so it refuses rather than remove it.
  - A new plugin has the same name as one no Yuzu package installed, or as a
    Yuzu plugin whose bytes were changed after installation.
  - The existing service requires signed plugins (`--plugin-require-signature`)
    and the package contains an unsigned plugin. Every release `.pkg` does.
- A first install of the stock package is **installed but not started**,
  because the agent will not run without a server trust anchor. An agent that
  was stopped is left stopped, including one disabled with
  `launchctl disable system/com.yuzu.agent`; a disabled agent that was still
  running is restarted and stays disabled for the next boot. Previously the installer loaded
  the service every time.
- Upgrades keep the existing service definition's arguments, every `YUZU_*`
  environment variable and the standard proxy variables. Previously an upgrade
  replaced `/Library/LaunchDaemons/com.yuzu.agent.plist`, losing anything added
  to it. Any other environment variable is dropped and named in
  `/var/log/install.log`. If the existing definition cannot be parsed, the
  package default is installed with a warning and the agent is not started;
  earlier settings must be re-applied.
- An unrecognized development app under the data directory is moved to
  `/var/db/yuzu-agent/quarantine/` and reported; it no longer blocks the install
  or `uninstall.sh`.

**What to check.**

- If a refusal names a `/usr/local` directory, make it root-owned and remove
  the group and world write bits. Then inspect the files it lists: changing
  the directory's mode does not change who wrote what is already in it. Do not
  `chown -R` them: that makes another account's files look root-installed.
- If the data directory is refused, never delete it: it holds the agent's
  identity and enrolment. Run `chmod go-w` on it, or restore its owner.
- For signed-plugin enforcement, remove `--plugin-require-signature` before
  upgrading to an unsigned package, or build a signed one.
- Fleet deployment: pre-stage the server address and trust anchor so the first
  install starts the agent. See
  [Deploying with MDM](../../deploy/packaging/macos/README.md#deploying-with-mdm).
- Rolling a fleet back to an older package and forward again is supported. A
  package from before this installer replaces the service definition with its
  default, so re-apply the server and trust settings after such a rollback.
- After a failed install there is nothing to clean up: the next package run
  repairs or discards any recovery state it finds under `/var/db/yuzu-agent`.

The opt-in signed-app development lane (Endpoint Security) additionally moves
the executable into `/Library/Application Support/YuzuAgent/YuzuAgent.app` and
always runs with `--no-auto-update`, which preserves the bundle signature.
Update that lane by installing a new package (for example through MDM), not
over the air. The development `.pkg` is intentionally unsigned; it is not a
customer-distribution lane. Before switching lanes, read the
[packaging and recovery runbook](../../deploy/packaging/macos/README.md) and the
[macOS development foundation](../macos-development-foundation.md).

## Deprecated: `--max-agents` / `YUZU_MAX_AGENTS` has no effect and will be removed (#6165)

**What changed.** `--max-agents` (env `YUZU_MAX_AGENTS`) was never enforced: the server has never capped how many agents connect. It is now marked deprecated. Setting it explicitly logs one startup warning; the default logs nothing. `GET /api/v1/settings/server-config` still returns `max_agents` for compatibility.

**What to check.** Remove `--max-agents` and `YUZU_MAX_AGENTS` from your service units, compose files and environment. When the flag is removed in a later release, an explicit `--max-agents` will stop the server from starting (unknown option), while a leftover `YUZU_MAX_AGENTS` will be ignored. A malformed leftover value (for example `YUZU_MAX_AGENTS=unlimited`) still stops the server from starting today, because the value is still parsed as a number. There is no replacement: the server does not cap how many agents connect; spread a large fleet across gateways. Do not use `--grpc-max-threads` to limit agents: it is a fleet-size ceiling that must stay above the connected-agent count (size it at about 1.5x that count); set below it, every RPC fails.

## Version Compatibility

| Server Version | Min Agent Version | Min Gateway Version | Notes |
|---|---|---|---|
| 0.1.x | 0.1.0 | 0.1.0 | Initial release family |
| 0.5.x | 0.5.0 | 0.5.0 | Compiler hardening flags (`-fstack-protector-strong`, `_FORTIFY_SOURCE=2`, full RELRO), config file permission enforcement (`0600` on Unix), SRI integrity attributes on CDN scripts, configurable trigger limit (default 2000), git-derived version strings, chargen instruction definitions. |
| 0.6.x – 0.9.x | same as 0.5.x | same as 0.5.x | No on-disk format changes from 0.5.x; upgrade directly to 0.10.x. |
| 0.10.x | 0.10.0 | 0.10.0 | Server-side schema migration runner wired into every SQLite store. Upgrading from 0.9.x or earlier is data-preserving: the first 0.10.x startup stamps each database at schema v1 and runs a one-time legacy compatibility shim for stores that historically added columns via silent `ALTER TABLE` (`api_token_store`, `instruction_store`, `patch_manager`, `policy_store`, `product_pack_store`, `response_store`). Failed migrations close the affected store's DB handle and are reported via `/readyz` with the failed store name — **check `/readyz`, not `/livez`, to confirm upgrade success**. |
| 0.15.x (next) | 0.12.0 | 0.12.0 | **The audit log is admin-only while RBAC is off, and audit reads are bounded (breaking; #5771).** Non-admin sessions and tokens get `403` on every `AuditLog:Read` surface until RBAC is enabled with a role holding it; legacy `GET /api/audit` clamps `limit` to 1000 and refuses `offset` above 10000; MCP `query_audit_log` rejects wrong-typed filters. Server restart only; see the section below. |
| 0.15.x (next) | 0.12.0 | 0.12.0 | **Fleet visualization three-tier layout + talking sockets + curved tube wires (PR 12).** `/viz/fleet` no longer renders machines on a single flat grid. Cubes now stack into three architectural tiers: frontend on the top Y plane, applications in the middle, databases on the bottom. Classification is heuristic — `classifyTier` reads listener-port hints (DB/web port sets) and process category, priority `db > web > app`. **Behavioural break for automation consumers:** if you scripted SIEM rules or dashboards that filter by "where a cube falls in the canvas", expect tier reassignments after upgrade. The wire change is *additive* — `schema_minor` bumps `3 → 4` with a new optional `local_addr` field on `ListenerSocket` carrying the kernel-reported bind address (server-side bounded at 64 bytes per field). Strict-validating consumers pinned to `schema_minor == 3` should relax their validator to `minimum: 3`. **Loopback-only listeners (`127.x`, `::1`, `[::1]`, `::ffff:127.x`) no longer appear on cube surfaces** — they're not reachable from other instances. **New talking-socket primitive:** each cube grows a ring of cool-blue dots on its BOTTOM face, one per unique outbound `(proto, dst_ip, dst_port)`; hover surfaces `talking: tcp → ip:port`. **Wire geometry changed:** cross-machine connections render as `THREE.TubeGeometry` along a `CubicBezierCurve3` with vertical end-tangents instead of 1px `THREE.Line` — wires drop straight down out of the source cube floor, run mostly-straight through space, and dock straight up into the destination's listener sphere. Screen-scrapers that parsed wire colour or geometry need updating. **Origin RGB `AxesHelper` removed** from the empty-scene scaffold — the three tier planes replace it as the orientation cue. **Default camera reframed** to `(45, 60, 45)` looking at the middle tier (was `(35, 30, 35)` looking at origin); bookmarked URLs will land on the new framing. Bundle size ~70 → ~84 KB. **Known limitation:** databases on non-standard ports (Postgres on 5431, etc.) misclassify as `app` tier unless their process is identified as `database` by the agent's process classifier. **Rolling-upgrade behaviour:** during a staged agent rollout, agents on a build older than the `tar.fleet_snapshot` action have no topology to push and appear in `/viz/fleet` as dimmed `stale` cubes until their agent is upgraded — this is expected, not a regression (previously such agents vanished from the visualization entirely once any agent pushed). **Kill-switch change:** `--viz-disable` now also `503`s the `/viz/fleet` and `/viz/host/<id>` page shells, not just the REST endpoints — an operator who sets the flag no longer sees a half-working page; it also writes a `server.viz_disabled` audit event at boot. **Governance Gate 7 hardening (no operator action required):** parser field caps on all agent-controlled strings, an IP-claim reclaim window so a crashed agent no longer strands its IPs forever, CAP-1 eviction keyed on the server clock, per-entry isolation in gateway `BatchHeartbeat` ingest, and a fix for a registration-replay storm under upstream flapping. **Scope-walking YAML `fromResultSet:` DSL (PR-E).** Policies whose `spec.scope:` used a `selector:` mapping block previously stored an empty scope (matched all devices — the selector was silently ignored). Existing rows are not migrated, but **re-creating or re-importing** such a policy after upgrade applies the selector as a real predicate and may narrow targeting — review the intended scope before re-import. Inline flow-mapping scope (`scope: {fromResultSet: x}`) is now rejected; use the block form. Result-set aliases referenced from `fromResultSet:` must be drawn from the `[A-Za-z0-9_.:*-]` charset (no spaces/quotes). **Inventory freshness gauge now server-clock-stamped (#1685).** `yuzu_inventory_stale_agents` keys on the server's receipt time, not the agent-supplied `collected_at`. A one-time migration (v3) at first 0.15.x startup clamps any `inventory_state` row whose `last_seen`/`first_seen` was stamped from a future-skewed agent clock back down to now. **Operator-visible:** if any agents had future-skewed clocks, the gauge may show a one-time *increase* post-upgrade as previously-hidden endpoints re-enter the staleness window with a fresh ~48h grace — genuinely active agents fall back out within two daily sync cycles; this is the intended security correction, not an incident. No operator action required (the `YuzuInventoryStaleAgents` alert ships disabled). **Rollback note:** downgrading the server below 0.15.x after v3 has run is data-safe (schema unchanged) but new inventory syncs revert to stamping `last_seen` from agent time, silently re-opening the clock-skew gap for those rows. **DEX application performance over time (opt-in).** New per-app, per-version CPU/working-set trend views (DEX → Performance → "Application performance over time"; REST `/api/v1/dex/perf/{apps,app,group}` + the `list_dex_perf_apps`/`get_dex_app_perf`/`get_dex_group_app_perf` MCP tools; per-device drill `GET /api/v1/dex/devices/{id}/app-perf`). **No action is required to upgrade, but the views are EMPTY until you opt in:** per-application sampling ships **off by default** (`procperf_enabled=false`) because it is usage-class telemetry (works-council-relevant). Enable `procperf_enabled=true` on the target devices via `tar.configure` (and leave the daily-sync master switch `--inventory-disable` unset). Data appears **after the first completed UTC midnight** on each opted-in device (the agent ships a daily summary, not immediately), and the trends lengthen as days accumulate (fleet ≤180 days, group ≤31 days). A freshly-enrolled or non-opted-in device shows an honest empty state ("no application performance history yet"), not a bug. The per-device drill is also reachable from a dashboard panel on the `/device` DEX lens ("Application performance over time" — same retained data, no live query, no `Execute` permission; no upgrade action needed). The per-device drill is behavioural PII — scoped + audited (`dex.device.app_perf.view`, fail-closed); the fleet and group aggregates suppress any app/version on fewer than 10 devices to a count only (no singling-out). **Response/execution reads fail closed on a corrupt RBAC store (#1634, partial).** The response readers (`query_responses` + `aggregate_responses` MCP tools, `GET /api/v1/executions/{id}/visualization`, `GET /api/responses/{id}` / `/aggregate` / `/export`) route through a per-agent management-group filter. **The only operator-visible change in this release** is fail-closed behavior under a **corrupt/load-failed `rbac.db`**: these surfaces now return zero rows (the legacy `/api/responses/{id}/aggregate` returns `503`) instead of exposing the whole fleet via the legacy read fallback. **Not yet changed:** under normal RBAC operation these reads are **not** management-group-scoped — a holder of global `Response:Read` still sees all agents' responses (the filter is inert under the current global gate; the gate change that makes scoping effective is tracked under #1634). RBAC explicitly disabled is unchanged. No operator action required. **MCP agentic write surface + A2 discovery + A4 error-shape (R2, #289 / #1794).** Five MCP write tools (`set_tag`/`delete_tag`/`approve_request`/`reject_request`/`quarantine_device`) ship with a ticket-then-recall approval flow, plus the `/api/v1/discover/*` discovery family. The approvals store gains additive `consumed_at` + `consumed_by` columns (auto-migrated at first startup; no operator action). **Breaking wire-shape change:** many `/api/v1` error bodies that were previously `{"error":"<string>"}` are now the nested A4 object `{"error":{"code","message","correlation_id",…}}` — a REST client that read `error` as a *string* must migrate to `error.code` / `error.message` (see `rest-api.md` §Error envelope). The MCP write surface is gated behind the existing tier model + a maker-checker approval workflow; audit `mcp.<tool>` covers every write. **NVD CVE-store schema migration (v1→v2) + full CPE version-range matching.** The server-side NVD store is reshaped on first startup (flat `cve` → normalized `cve` + `cve_match`); `/api/nvd/match` now evaluates real CPE version ranges. **Operator-visible on upgrade:** (a) the migration **drops and rebuilds the local CVE mirror** — vulnerability-matching coverage is reduced until the next NVD sync completes (rate-limited; up to a few hours without an API key), self-healing and logged with a warning at migration time; (b) `GET /api/nvd/status` `total_cves` now counts **distinct CVEs** (was one row per affected product) so it reads **lower** after upgrade even once fully synced, and near-zero during the rebuild window — **expected, not data loss**. Any SIEM/dashboard alerting on the `total_cves` magnitude should be re-baselined. No config change or action required. **NVD CVE sync now actually runs (was dormant).** A `rate_limit()` integer overflow meant the server-side NVD sync slept ~292 years before its first request, so it never populated on any prior deployment (`/api/nvd/status` `total_cves` stayed at the built-in seed). It now runs on startup. **Operator-visible:** (a) the server makes **new outbound HTTPS requests to `services.nvd.nist.gov`** — restricted-egress / air-gapped deployments that silently never reached it before may now log connection failures (set `--no-nvd-sync` to disable, or `--nvd-proxy`); (b) `total_cves` grows from the seed as the (keyword-scoped) sync populates. No config change required to benefit. **OIDC JWT signature verification now enforced on the Windows server (#1856/#1782, CRITICAL).** A Windows *server* build previously **skipped OIDC `id_token` signature verification entirely** — accepting forged RS256/384/512 tokens (session minting / account takeover). It now verifies on every platform via the same OpenSSL path. **Operator-visible only if you run a Windows server with OIDC SSO:** verification now genuinely depends on the IdP's JWKS being reachable, so a misconfigured or unreachable `jwks_uri` that the old Windows build *silently tolerated* (by accepting everything) will now cause **all OIDC logins to fail closed**. **Before upgrading a Windows + OIDC deployment**, confirm the server can reach the IdP `jwks_uri` and that system clock skew is within tolerance; if OIDC logins start failing fleet-wide post-upgrade, check JWKS reachability first. Local-password and API-token auth are unaffected; Linux/macOS servers already verified and are unchanged. **MCP `execute_instruction`'s zero-agents-reached response schema gained three new fields and a widened `status` enum (#3424/#3511).** The published `outputSchema`'s `oneOf` grew from 2 branches to 5: the success branch is unchanged, but the single `{status:"no_agents_reached", ...}` zero-reach branch is now four mutually-exclusive branches — `no_agents_reached` (same trigger condition, but now REQUIRES `retry_after_ms` where it was previously absent/unspecified), plus new `quarantined`, `containment_unreadable`, and `plugin_not_found` — each REQUIRING three new fields that were not previously present: `retry_after_ms` (a per-branch `const` — `5000` for the two retryable branches `containment_unreadable` and `no_agents_reached`, `null` for the two permanent branches `quarantined` and `plugin_not_found`), `agents_quarantined`, and `agents_unknown_plugin` (integer counts, present on every zero-reach branch regardless of which status matched). **Strict-validating consumers pinned to the old 2-branch `oneOf` or the old `no_agents_reached`-only zero-reach shape will reject a response using one of the three new statuses, or reject the new required fields on the shape they already recognized.** Relax any pinned `oneOf`/`const` validation to accept the widened schema (`GET /mcp/v1/` `tools/list` always reflects the current, authoritative shape) before upgrading an agentic client with strict response validation. A client that only branches on `status == "no_agents_reached"` string-equality (rather than treating an unrecognized status as "some non-retryable or retryable failure, check `message`") should add explicit handling for the three new values — see `docs/user-manual/mcp.md`'s `execute_instruction` row for the full semantics and retry guidance. **Alert-rule change (action may be required if you maintain a fork).** `YuzuDispatchTargetRejected`'s exclusion widens from `reason!="quarantined"` alone to `reason!~"quarantined\|unknown_plugin"` — same reasoning as the #881 exclusion above: a misconfigured automation retrying against an absent plugin is a caller mistake, not a fleet outage, and without the exclusion it clears the alert's `>3/15m` threshold on its own. If you maintain a fork of `docs/prometheus/yuzu-alerts.yml`, apply the same widened exclusion (`!~`, not `=~` — the fork's rule excludes both reasons, it does not match only them). |
| 0.15.x (next) | 0.12.0 | 0.12.0 | **Fleet visualization three-tier layout + talking sockets + curved tube wires (PR 12).** `/viz/fleet` no longer renders machines on a single flat grid. Cubes now stack into three architectural tiers: frontend on the top Y plane, applications in the middle, databases on the bottom. Classification is heuristic — `classifyTier` reads listener-port hints (DB/web port sets) and process category, priority `db > web > app`. **Behavioural break for automation consumers:** if you scripted SIEM rules or dashboards that filter by "where a cube falls in the canvas", expect tier reassignments after upgrade. The wire change is *additive* — `schema_minor` bumps `3 → 4` with a new optional `local_addr` field on `ListenerSocket` carrying the kernel-reported bind address (server-side bounded at 64 bytes per field). Strict-validating consumers pinned to `schema_minor == 3` should relax their validator to `minimum: 3`. **Loopback-only listeners (`127.x`, `::1`, `[::1]`, `::ffff:127.x`) no longer appear on cube surfaces** — they're not reachable from other instances. **New talking-socket primitive:** each cube grows a ring of cool-blue dots on its BOTTOM face, one per unique outbound `(proto, dst_ip, dst_port)`; hover surfaces `talking: tcp → ip:port`. **Wire geometry changed:** cross-machine connections render as `THREE.TubeGeometry` along a `CubicBezierCurve3` with vertical end-tangents instead of 1px `THREE.Line` — wires drop straight down out of the source cube floor, run mostly-straight through space, and dock straight up into the destination's listener sphere. Screen-scrapers that parsed wire colour or geometry need updating. **Origin RGB `AxesHelper` removed** from the empty-scene scaffold — the three tier planes replace it as the orientation cue. **Default camera reframed** to `(45, 60, 45)` looking at the middle tier (was `(35, 30, 35)` looking at origin); bookmarked URLs will land on the new framing. Bundle size ~70 → ~84 KB. **Known limitation:** databases on non-standard ports (Postgres on 5431, etc.) misclassify as `app` tier unless their process is identified as `database` by the agent's process classifier. **Rolling-upgrade behaviour:** during a staged agent rollout, agents on a build older than the `tar.fleet_snapshot` action have no topology to push and appear in `/viz/fleet` as dimmed `stale` cubes until their agent is upgraded — this is expected, not a regression (previously such agents vanished from the visualization entirely once any agent pushed). **Kill-switch change:** `--viz-disable` now also `503`s the `/viz/fleet` and `/viz/host/<id>` page shells, not just the REST endpoints — an operator who sets the flag no longer sees a half-working page; it also writes a `server.viz_disabled` audit event at boot. **Governance Gate 7 hardening (no operator action required):** parser field caps on all agent-controlled strings, an IP-claim reclaim window so a crashed agent no longer strands its IPs forever, CAP-1 eviction keyed on the server clock, per-entry isolation in gateway `BatchHeartbeat` ingest, and a fix for a registration-replay storm under upstream flapping. **Scope-walking YAML `fromResultSet:` DSL (PR-E).** Policies whose `spec.scope:` used a `selector:` mapping block previously stored an empty scope (matched all devices — the selector was silently ignored). Existing rows are not migrated, but **re-creating or re-importing** such a policy after upgrade applies the selector as a real predicate and may narrow targeting — review the intended scope before re-import. Inline flow-mapping scope (`scope: {fromResultSet: x}`) is now rejected; use the block form. Result-set aliases referenced from `fromResultSet:` must be drawn from the `[A-Za-z0-9_.:*-]` charset (no spaces/quotes). **Inventory freshness gauge now server-clock-stamped (#1685).** `yuzu_inventory_stale_agents` keys on the server's receipt time, not the agent-supplied `collected_at`. A one-time migration (v3) at first 0.15.x startup clamps any `inventory_state` row whose `last_seen`/`first_seen` was stamped from a future-skewed agent clock back down to now. **Operator-visible:** if any agents had future-skewed clocks, the gauge may show a one-time *increase* post-upgrade as previously-hidden endpoints re-enter the staleness window with a fresh ~48h grace — genuinely active agents fall back out within two daily sync cycles; this is the intended security correction, not an incident. No operator action required (the `YuzuInventoryStaleAgents` alert ships disabled). **Rollback note:** downgrading the server below 0.15.x after v3 has run is data-safe (schema unchanged) but new inventory syncs revert to stamping `last_seen` from agent time, silently re-opening the clock-skew gap for those rows. **DEX application performance over time (opt-in).** New per-app, per-version CPU/working-set trend views (DEX → Performance → "Application performance over time"; REST `/api/v1/dex/perf/{apps,app,group}` + the `list_dex_perf_apps`/`get_dex_app_perf`/`get_dex_group_app_perf` MCP tools; per-device drill `GET /api/v1/dex/devices/{id}/app-perf`). **No action is required to upgrade, but the views are EMPTY until you opt in:** per-application sampling ships **off by default** (`procperf_enabled=false`) because it is usage-class telemetry (works-council-relevant). Enable `procperf_enabled=true` on the target devices via `tar.configure` (and leave the daily-sync master switch `--inventory-disable` unset). Data appears **after the first completed UTC midnight** on each opted-in device (the agent ships a daily summary, not immediately), and the trends lengthen as days accumulate (fleet ≤180 days, group ≤31 days). A freshly-enrolled or non-opted-in device shows an honest empty state ("no application performance history yet"), not a bug. The per-device drill is also reachable from a dashboard panel on the `/device` DEX lens ("Application performance over time" — same retained data, no live query, no `Execute` permission; no upgrade action needed). The per-device drill is behavioural PII — scoped + audited (`dex.device.app_perf.view`, fail-closed); the fleet and group aggregates suppress any app/version on fewer than 10 devices to a count only (no singling-out). **Response/execution reads fail closed on a corrupt RBAC store (#1634, partial).** The response readers (`query_responses` + `aggregate_responses` MCP tools, `GET /api/v1/executions/{id}/visualization`, `GET /api/responses/{id}` / `/aggregate` / `/export`) route through a per-agent management-group filter. **The only operator-visible change in this release** is fail-closed behavior under a **corrupt/load-failed `rbac.db`**: these surfaces now return zero rows (the legacy `/api/responses/{id}/aggregate` returns `503`) instead of exposing the whole fleet via the legacy read fallback. **Not yet changed:** under normal RBAC operation these reads are **not** management-group-scoped — a holder of global `Response:Read` still sees all agents' responses (the filter is inert under the current global gate; the gate change that makes scoping effective is tracked under #1634). RBAC explicitly disabled is unchanged. No operator action required. **MCP agentic write surface + A2 discovery + A4 error-shape (R2, #289 / #1794).** Five MCP write tools (`set_tag`/`delete_tag`/`approve_request`/`reject_request`/`quarantine_device`) ship with a ticket-then-recall approval flow, plus the `/api/v1/discover/*` discovery family. The approvals store gains additive `consumed_at` + `consumed_by` columns (auto-migrated at first startup; no operator action). **Breaking wire-shape change:** many `/api/v1` error bodies that were previously `{"error":"<string>"}` are now the nested A4 object `{"error":{"code","message","correlation_id",…}}` — a REST client that read `error` as a *string* must migrate to `error.code` / `error.message` (see `rest-api.md` §Error envelope). The MCP write surface is gated behind the existing tier model + a maker-checker approval workflow; audit `mcp.<tool>` covers every write. **NVD CVE-store schema migration (v1→v2) + full CPE version-range matching.** The server-side NVD store is reshaped on first startup (flat `cve` → normalized `cve` + `cve_match`); `/api/nvd/match` now evaluates real CPE version ranges. **Operator-visible on upgrade:** (a) the migration **drops and rebuilds the local CVE mirror** — vulnerability-matching coverage is reduced until the next NVD sync completes (rate-limited; up to a few hours without an API key), self-healing and logged with a warning at migration time; (b) `GET /api/nvd/status` `total_cves` now counts **distinct CVEs** (was one row per affected product) so it reads **lower** after upgrade even once fully synced, and near-zero during the rebuild window — **expected, not data loss**. Any SIEM/dashboard alerting on the `total_cves` magnitude should be re-baselined. No config change or action required. **NVD CVE sync now actually runs (was dormant).** A `rate_limit()` integer overflow meant the server-side NVD sync slept ~292 years before its first request, so it never populated on any prior deployment (`/api/nvd/status` `total_cves` stayed at the built-in seed). It now runs on startup. **Operator-visible:** (a) the server makes **new outbound HTTPS requests to `services.nvd.nist.gov`** — restricted-egress / air-gapped deployments that silently never reached it before may now log connection failures (set `--no-nvd-sync` to disable, or `--nvd-proxy`); (b) `total_cves` grows from the seed as the sync populates. No config change required to benefit. **NVD sync now builds the FULL CVE catalog (newest-first), not ~20 keywords.** The sync backfills every CVE published within a configurable window — `--nvd-backfill-years` / `YUZU_NVD_BACKFILL_YEARS` (default **8 years**; `0` = full history) — newest-first and **resumable across restarts**, then settles into a periodic last-modified freshness re-check. **Operator-visible:** the server makes sustained HTTPS requests to `services.nvd.nist.gov`, the local NVD DB grows into the hundreds of MB, and `/api/nvd/status` `total_cves` climbs continuously while `backfill_complete` stays `false` until the backfill floor is first reached — `last_sync_time` advances after every successful fetch window and is **not** a completion signal (use the new `backfill_complete` + `backfill_oldest_published` fields, and the `yuzu_nvd_total_cves` / `yuzu_nvd_backfill_complete` metrics, for progress). **`/api/nvd/status` `enabled` semantics corrected:** it now reflects whether sync is configured on, so under `--no-nvd-sync` it reports `enabled:false` (was `true`); a monitor keying on `enabled` to mean "mirror usable" should check `total_cves` instead. The initial backfill is NVD-rate-limited (hours without an `--nvd-api-key`, minutes with one) and resumes where it left off if interrupted. Set `--no-nvd-sync` to disable, `--nvd-proxy` for restricted egress. Product matching stays name-based (vendor-precise CPE identity pending ADR-0018). **Certificate inventory now reads System/SystemRoot keychains and Linux `/etc/ssl/certs` natively (no more `openssl`/`security` CLI shell-out for those stores).** The `certificates` plugin's `list`/`details`/`delete` actions are unchanged in output shape (same pipe-delimited columns, same field values) — this is a collection-mechanism change only, verified byte-parity against the prior CLI-based output. The macOS login keychain read has ALSO moved off its governed-shell path in this same release (#3406): it now runs as a pre-split argv through the bounded runner, with the console user's home directory resolved in-process instead of by the shell. Output shape is unchanged. **One operator-visible correction:** when the console user cannot be determined — most often a slow or unreachable directory service on a domain-joined Mac — `certificates.list`/`details` with `store=login` or `all` now return an explicit `not_available|<reason>` row and mark the result PARTIAL. Previously that case silently dropped the login keychain and the list read as complete, and `details` could answer a confident `not_found` for a certificate it had never looked for. Expect to SEE partial results where output previously looked clean on such hosts; that is the bug being fixed, not a regression. No operator action required; mixed old/new-agent fleets and rollback are safe (no server-side or schema change). |
| 0.15.x (next) | 0.12.0 | 0.12.0 | **Fleet visualization three-tier layout + talking sockets + curved tube wires (PR 12).** `/viz/fleet` no longer renders machines on a single flat grid. Cubes now stack into three architectural tiers: frontend on the top Y plane, applications in the middle, databases on the bottom. Classification is heuristic — `classifyTier` reads listener-port hints (DB/web port sets) and process category, priority `db > web > app`. **Behavioural break for automation consumers:** if you scripted SIEM rules or dashboards that filter by "where a cube falls in the canvas", expect tier reassignments after upgrade. The wire change is *additive* — `schema_minor` bumps `3 → 4` with a new optional `local_addr` field on `ListenerSocket` carrying the kernel-reported bind address (server-side bounded at 64 bytes per field). Strict-validating consumers pinned to `schema_minor == 3` should relax their validator to `minimum: 3`. **Loopback-only listeners (`127.x`, `::1`, `[::1]`, `::ffff:127.x`) no longer appear on cube surfaces** — they're not reachable from other instances. **New talking-socket primitive:** each cube grows a ring of cool-blue dots on its BOTTOM face, one per unique outbound `(proto, dst_ip, dst_port)`; hover surfaces `talking: tcp → ip:port`. **Wire geometry changed:** cross-machine connections render as `THREE.TubeGeometry` along a `CubicBezierCurve3` with vertical end-tangents instead of 1px `THREE.Line` — wires drop straight down out of the source cube floor, run mostly-straight through space, and dock straight up into the destination's listener sphere. Screen-scrapers that parsed wire colour or geometry need updating. **Origin RGB `AxesHelper` removed** from the empty-scene scaffold — the three tier planes replace it as the orientation cue. **Default camera reframed** to `(45, 60, 45)` looking at the middle tier (was `(35, 30, 35)` looking at origin); bookmarked URLs will land on the new framing. Bundle size ~70 → ~84 KB. **Known limitation:** databases on non-standard ports (Postgres on 5431, etc.) misclassify as `app` tier unless their process is identified as `database` by the agent's process classifier. **Rolling-upgrade behaviour:** during a staged agent rollout, agents on a build older than the `tar.fleet_snapshot` action have no topology to push and appear in `/viz/fleet` as dimmed `stale` cubes until their agent is upgraded — this is expected, not a regression (previously such agents vanished from the visualization entirely once any agent pushed). **Kill-switch change:** `--viz-disable` now also `503`s the `/viz/fleet` and `/viz/host/<id>` page shells, not just the REST endpoints — an operator who sets the flag no longer sees a half-working page; it also writes a `server.viz_disabled` audit event at boot. **Governance Gate 7 hardening (no operator action required):** parser field caps on all agent-controlled strings, an IP-claim reclaim window so a crashed agent no longer strands its IPs forever, CAP-1 eviction keyed on the server clock, per-entry isolation in gateway `BatchHeartbeat` ingest, and a fix for a registration-replay storm under upstream flapping. **Scope-walking YAML `fromResultSet:` DSL (PR-E).** Policies whose `spec.scope:` used a `selector:` mapping block previously stored an empty scope (matched all devices — the selector was silently ignored). Existing rows are not migrated, but **re-creating or re-importing** such a policy after upgrade applies the selector as a real predicate and may narrow targeting — review the intended scope before re-import. Inline flow-mapping scope (`scope: {fromResultSet: x}`) is now rejected; use the block form. Result-set aliases referenced from `fromResultSet:` must be drawn from the `[A-Za-z0-9_.:*-]` charset (no spaces/quotes). **Inventory freshness gauge now server-clock-stamped (#1685).** `yuzu_inventory_stale_agents` keys on the server's receipt time, not the agent-supplied `collected_at`. A one-time migration (v3) at first 0.15.x startup clamps any `inventory_state` row whose `last_seen`/`first_seen` was stamped from a future-skewed agent clock back down to now. **Operator-visible:** if any agents had future-skewed clocks, the gauge may show a one-time *increase* post-upgrade as previously-hidden endpoints re-enter the staleness window with a fresh ~48h grace — genuinely active agents fall back out within two daily sync cycles; this is the intended security correction, not an incident. No operator action required (the `YuzuInventoryStaleAgents` alert ships disabled). **Rollback note:** downgrading the server below 0.15.x after v3 has run is data-safe (schema unchanged) but new inventory syncs revert to stamping `last_seen` from agent time, silently re-opening the clock-skew gap for those rows. **DEX application performance over time (opt-in).** New per-app, per-version CPU/working-set trend views (DEX → Performance → "Application performance over time"; REST `/api/v1/dex/perf/{apps,app,group}` + the `list_dex_perf_apps`/`get_dex_app_perf`/`get_dex_group_app_perf` MCP tools; per-device drill `GET /api/v1/dex/devices/{id}/app-perf`). **No action is required to upgrade, but the views are EMPTY until you opt in:** per-application sampling ships **off by default** (`procperf_enabled=false`) because it is usage-class telemetry (works-council-relevant). Enable `procperf_enabled=true` on the target devices via `tar.configure` (and leave the daily-sync master switch `--inventory-disable` unset). Data appears **after the first completed UTC midnight** on each opted-in device (the agent ships a daily summary, not immediately), and the trends lengthen as days accumulate (fleet ≤180 days, group ≤31 days). A freshly-enrolled or non-opted-in device shows an honest empty state ("no application performance history yet"), not a bug. The per-device drill is also reachable from a dashboard panel on the `/device` DEX lens ("Application performance over time" — same retained data, no live query, no `Execute` permission; no upgrade action needed). The per-device drill is behavioural PII — scoped + audited (`dex.device.app_perf.view`, fail-closed); the fleet and group aggregates suppress any app/version on fewer than 10 devices to a count only (no singling-out). **Response/execution reads fail closed on a corrupt RBAC store (#1634, partial).** The response readers (`query_responses` + `aggregate_responses` MCP tools, `GET /api/v1/executions/{id}/visualization`, `GET /api/responses/{id}` / `/aggregate` / `/export`) route through a per-agent management-group filter. **The only operator-visible change in this release** is fail-closed behavior under a **corrupt/load-failed `rbac.db`**: these surfaces now return zero rows (the legacy `/api/responses/{id}/aggregate` returns `503`) instead of exposing the whole fleet via the legacy read fallback. **Not yet changed:** under normal RBAC operation these reads are **not** management-group-scoped — a holder of global `Response:Read` still sees all agents' responses (the filter is inert under the current global gate; the gate change that makes scoping effective is tracked under #1634). RBAC explicitly disabled is unchanged. No operator action required. **MCP agentic write surface + A2 discovery + A4 error-shape (R2, #289 / #1794).** Five MCP write tools (`set_tag`/`delete_tag`/`approve_request`/`reject_request`/`quarantine_device`) ship with a ticket-then-recall approval flow, plus the `/api/v1/discover/*` discovery family. The approvals store gains additive `consumed_at` + `consumed_by` columns (auto-migrated at first startup; no operator action). **Breaking wire-shape change:** many `/api/v1` error bodies that were previously `{"error":"<string>"}` are now the nested A4 object `{"error":{"code","message","correlation_id",…}}` — a REST client that read `error` as a *string* must migrate to `error.code` / `error.message` (see `rest-api.md` §Error envelope). The MCP write surface is gated behind the existing tier model + a maker-checker approval workflow; audit `mcp.<tool>` covers every write. **NVD CVE-store schema migration (v1→v2) + full CPE version-range matching.** The server-side NVD store is reshaped on first startup (flat `cve` → normalized `cve` + `cve_match`); `/api/nvd/match` now evaluates real CPE version ranges. **Operator-visible on upgrade:** (a) the migration **drops and rebuilds the local CVE mirror** — vulnerability-matching coverage is reduced until the next NVD sync completes (rate-limited; up to a few hours without an API key), self-healing and logged with a warning at migration time; (b) `GET /api/nvd/status` `total_cves` now counts **distinct CVEs** (was one row per affected product) so it reads **lower** after upgrade even once fully synced, and near-zero during the rebuild window — **expected, not data loss**. Any SIEM/dashboard alerting on the `total_cves` magnitude should be re-baselined. No config change or action required. **NVD CVE sync now actually runs (was dormant).** A `rate_limit()` integer overflow meant the server-side NVD sync slept ~292 years before its first request, so it never populated on any prior deployment (`/api/nvd/status` `total_cves` stayed at the built-in seed). It now runs on startup. **Operator-visible:** (a) the server makes **new outbound HTTPS requests to `services.nvd.nist.gov`** — restricted-egress / air-gapped deployments that silently never reached it before may now log connection failures (set `--no-nvd-sync` to disable, or `--nvd-proxy`); (b) `total_cves` grows from the seed as the sync populates. No config change required to benefit. **NVD sync now builds the FULL CVE catalog (newest-first), not ~20 keywords.** The sync backfills every CVE published within a configurable window — `--nvd-backfill-years` / `YUZU_NVD_BACKFILL_YEARS` (default **8 years**; `0` = full history) — newest-first and **resumable across restarts**, then settles into a periodic last-modified freshness re-check. **Operator-visible:** the server makes sustained HTTPS requests to `services.nvd.nist.gov`, the local NVD DB grows into the hundreds of MB, and `/api/nvd/status` `total_cves` climbs continuously while `backfill_complete` stays `false` until the backfill floor is first reached — `last_sync_time` advances after every successful fetch window and is **not** a completion signal (use the new `backfill_complete` + `backfill_oldest_published` fields, and the `yuzu_nvd_total_cves` / `yuzu_nvd_backfill_complete` metrics, for progress). **`/api/nvd/status` `enabled` semantics corrected:** it now reflects whether sync is configured on, so under `--no-nvd-sync` it reports `enabled:false` (was `true`); a monitor keying on `enabled` to mean "mirror usable" should check `total_cves` instead. The initial backfill is NVD-rate-limited (hours without an `--nvd-api-key`, minutes with one) and resumes where it left off if interrupted. Set `--no-nvd-sync` to disable, `--nvd-proxy` for restricted egress. Product matching stays name-based (vendor-precise CPE identity pending ADR-0018). **Certificate inventory now reads System/SystemRoot keychains and Linux `/etc/ssl/certs` natively (no more `openssl`/`security` CLI shell-out for those stores).** The `certificates` plugin's `list`/`details`/`delete` actions are unchanged in output shape (same pipe-delimited columns, same field values) — this is a collection-mechanism change only, verified byte-parity against the prior CLI-based output. The macOS login keychain is unchanged (still reads via the existing governed-shell path, a deliberate exception — see `docs/agent-spawn-sink-manifest.md`). No operator action required; mixed old/new-agent fleets and rollback are safe (no server-side or schema change). |
| 0.15.x (next) | 0.12.0 | 0.12.0 | **`PatchManager` now runs on PostgreSQL (ADR-0062).** `/api/patches/*` (patch inventory + deployment tracking) moved off its own `patches.db` SQLite file onto the shared Postgres substrate (schema `patch_manager`). **No data carries over from a pre-Postgres install** (fresh-start-by-default, ADR-0009) — any deployment record that existed before upgrade is gone and must be re-created via `POST /api/patches/deploy`. Server startup now fails closed if the `patch_manager` schema can't be created/opened — a posture upgrade from the SQLite era, where construction was unconditional/best-effort and no caller ever checked whether the store had actually opened; confirm success via `/readyz` (`patch_manager` is now reported by both `/readyz` and `/healthz`, absent from both before this release). **Removed: automatic patch-deployment orchestration.** `PatchManager::execute_deployment()` (the scan → install → verify → reboot workflow) had zero production callers on any released build — nothing ever wired a dispatch/OS-lookup callback to it — and is deleted, not ported; `POST /api/patches/deploy` still creates a deployment + per-target rows, but nothing in the server drives them through that workflow automatically (see #3669, filed alongside this change, and `docs/capability-map.md` §8.3/§8.4/§8.6). **Patch inventory (`GET /api/patches`) is separately unwired**: `record_patches()`, the only method that writes it, also has no production caller — this predates the migration and is not something upgrading changes — so `GET /api/patches` returns empty in every real deployment today; see `docs/capability-map.md` §8.5/§8.7 and #3676. No operator action required beyond re-creating any in-flight deployment after upgrade. |
| 0.15.x (next) | 0.12.0 | 0.12.0 | **`WorkflowEngine` now runs on PostgreSQL (ADR-0064).** `/api/workflows*` and `/api/workflow-executions/*` moved off `workflows.db` SQLite onto the shared Postgres substrate (schema `workflow_engine`). **No data carries over from a pre-Postgres install** (fresh-start-by-default, ADR-0009) — any workflow definition and its execution history that existed before upgrade is gone; re-create workflows via `POST /api/workflows` (or product-pack re-install). Server startup now fails closed if the `workflow_engine` schema can't be created/opened — a posture upgrade from the SQLite era, where construction was unconditional/best-effort and no caller ever checked whether the store had actually opened; confirm success via `/readyz` (already reported before this release) and `/healthz` (newly reported — was absent before this release). **Delete semantics changed: `DELETE /api/workflows/:id` now soft-deletes.** The response shape is unchanged (`{"deleted": true|false}`), but a deleted workflow's row and its execution history are now retained internally rather than orphaned — this is not operator-visible today (no "show deleted workflows" surface exists), but a deleted workflow's `id` can never be reused. No operator action required. |
| 0.15.x (next) | 0.12.0 | 0.12.0 | **Guardian file-hash `max_bytes` now has a hard ceiling (#2233).** An authored `file-hash-equals` rule's `max_bytes` (the hashing-DoS cap) was previously accepted unbounded from the authoring API. It is now clamped to 1 GiB (`kMaxFileHashBytes`) on the agent, and the server rejects a new/edited rule authoring a value above that ceiling in either JSON wire form (400). **Operator-visible only if you have a PRE-EXISTING `file-hash-equals` rule authored (before this release) with `max_bytes` above 1 GiB, watching a file at or above that size:** after upgrade, that file reports `<oversize>` instead of being hashed — a compliance-verdict change with no authoring-time signal (the rule already exists, so the new server-side reject cannot retroactively catch it). List your rules via `GET /api/v1/guaranteed-state/rules` (the route returns every rule; there is no server-side filter), check any `file-hash-equals` rule for `max_bytes` over 1073741824, and re-author within the ceiling if the larger cap was intentional. No operator action required otherwise. **DEX and management-group reads now fail closed on a degraded read instead of answering a healthy/empty result (#4855, #1762)** — see "Behaviour change: DEX device score and management-group member reads now fail closed on a degraded read (#4855, #1762)" below. |
| 0.15.x (next) | 0.12.0 | 0.12.0 | **`BatchHeartbeatResponse` gains `unknown_session_ids` and `unknown_session_ids_truncated` (#1197), and the gateway now acts on them - restart the gateway to deploy (this disconnects every agent it holds, and released v0.13.0 and v0.14.0-rc6 agents stayed wedged after a graceful gateway restart in testing, so upgrade agents to a build with the #5183 fix first or expect to restart the agent service on them; see "Agent dependency" in [What happens when the server restarts](gateway.md#what-happens-when-the-server-restarts)); no wire change and no new required configuration.** The server lists, per `BatchHeartbeat`, the session ids it does not hold, and the new gateway reads that list and re-registers exactly the sessions it still holds (the registration-replay drip, bounded by a per-session guard and a queue cap). The behavioural change is that, after a server restart, agents behind a new gateway become known to the server again without operator action; before, they stayed unknown (`/health` `agents.online` stayed 0 in the observed runs). Any pairing interoperates: an OLD server never sends the fields, so a new gateway sees an empty list and does nothing; an OLD gateway ignores the added response fields (proto3 unknown fields, field numbers 2 and 3) and keeps the old behaviour. Recovery needs the new gateway and a server that sends the fields. Observed on a local rig: the agent was known again about 17 s after the server was healthy, on its first heartbeat after that; after an outage long enough to open the gateway circuit breaker, recovery waits for the breaker's remaining backoff (58 s observed after a 300 s outage with 1 agent; with 10 and 30 agents the breaker opened in later runs and the breaker's own replay recovered them, with all agents online 85.2 s and 50.4 s after the server was healthy; the backoff is capped at 300 s, and steps above 160 s were not observed). A second operator-visible change is a new `yuzu_server_gateway_route_desync_total{op="batch_heartbeat",outcome="malformed_session_id"}` series (pre-seeded at 0, expected to stay 0, no alert): over-length (more than 64 bytes) unknown session ids in a `BatchHeartbeat` are now counted under that series, per entry, instead of under `op="renew_leases", outcome="unknown_session"`. The gateway adds three counters and two optional application-env tunables, described under [What happens when the server restarts](gateway.md#what-happens-when-the-server-restarts), which also states what the reconcile does not promise (fleet completion inside a route lease, dispatch reachability after the session is adopted, several core replicas). |
| 0.15.x (next) | 0.12.0 | 0.12.0 | **Gateway session ids are now resolved against the durable Postgres route directory (HA WS-5 slice 2, ADR-2002 §7f); server restart only, no gateway restart, no flag, no migration, no proto field.** Heartbeat, inventory and stream-status RPCs look a presented `session_id` up in `gateway_route_store.agent_routes` instead of one replica's in-memory map. After a server-only restart the server still lists directory-known sessions in `unknown_session_ids` so the gateway replays `ProxyRegister` and rebuilds the local registry (drip-paced; ~1200 s for 10k agents at 100 ms), while leases keep renewing; this needs a gateway with the #1197 reconcile (an older gateway gives the pre-reconcile behaviour). **Rolling deploy:** an old replica reports directory-known sessions as unknown, so drain old replicas first. Run exactly ONE server replica until the safe-to-scale gate lifts (ADR-2002 §7c); this change does not lift it. Rollback to the previous binary is safe. A degraded directory read is fail-soft for heartbeats; a `NotifyStreamStatus` CONNECTED during it is accepted only for a session this replica holds locally and is otherwise refused (`connected_unverified`; the agent regains dispatch at its next reconnect). A session id matching more than one live row is refused and pages `YuzuGatewaySessionAmbiguous`; a `ProxyRegister` replay presenting an id another agent's row holds is refused and pages `YuzuGatewaySessionHeldByOtherAgent`. See [gateway.md](gateway.md#what-happens-when-the-server-restarts). |
| 0.15.x (next) | 0.12.0 | 0.12.0 | **Gateway heartbeat admission is now bound to the connection that opened the session (gateway restart required; breaking for L7-fronted gateways).** The gateway admits an agent `Heartbeat` only on the HTTP/2 connection that opened the session's `Subscribe` stream; any other heartbeat is answered `NOT_FOUND` and not forwarded. Deploy with a gateway restart, and check for an HTTP/2-terminating hop in front of `:50051` first. A rejected agent recovers by re-registering. That logic exists from v0.13.0, but the released v0.13.0 and v0.14.0-rc6 agents wedge in their reconnect path with default settings (bug #2182, fixed by PR #5183, in no release yet) and recover only with `--no-auto-update`; v0.12.0 never recovers by itself (observed; older versions were not tested). Upgrade the agents first, then the gateway, with a build that includes the #2182 fix once released; until then restart an agent that stays rejected. Agents that do not connect through the gateway are not affected by this requirement (see Older agents). No wire or server change. See the section "Breaking: gateways fronted by an HTTP/2-terminating proxy or mesh sidecar" below and [Heartbeat admission](gateway.md#heartbeat-admission). |
| 0.15.x (next) | 0.12.0 | 0.12.0 | **`--gateway-upstream` now refuses to start without gateway peer authorization (breaking for own-certificate and plaintext installs).** The gateway-upstream service admits only a gateway whose certificate key (SPKI SHA-256) is pinned, which carries `serverAuth` and is inside its validity window; the server exits at boot, before binding a port, when `--gateway-upstream` is set and that cannot be arranged. Generated default certificates are pinned automatically; your own certificates need `--gateway-peer-pin` / `--gateway-peer-pin-file` first; a plaintext (`--no-tls`) rig needs `--insecure-gateway-peer`; the Linux package unit passes `--gateway-upstream` unconditionally. Agents and gateways are unaffected on the wire. See the section "Breaking: `--gateway-upstream` now refuses to start without gateway peer authorization" below. |
| 0.15.x (next) | 0.12.0 | 0.12.0 | **The gateway now holds stream-status notifications instead of dropping them (#4632; gateway restart required).** Deploy it with a gateway restart, which disconnects every agent the node holds, so read "Upgrade day" and "Agent dependency" in [What happens when the server restarts](gateway.md#what-happens-when-the-server-restarts) first (released v0.13.0 and v0.14.0-rc6 agents do not recover by themselves after a gateway restart). **Read the [Gateway upgrade note for #4632](#gateway-upgrade-note-stream-status-notifications-and-startup-checks-4632) before you restart: a gateway whose configured `cluster_id` cannot be represented as UTF-8 now refuses to start.** There is no hot code load for this change: the upstream client's `code_change` is the identity function while its state gained fields, so deploy it by restart, not by a hot upgrade (INFERRED from the code, not run). No wire change and no change to the minimum agent or server version: `NotifyStreamStatus` is unchanged, so any pairing interoperates. What changes: a `CONNECTED` or `DISCONNECTED` notification that arrives while 10 are in flight or the circuit breaker is open is held in a bounded, memory-only store and sent first in first out, where the old gateway dropped it; when the breaker goes half open the new gateway sends one held notification as the probe, where the old one let up to 10 notifications through; and an agent-supplied peer address is sanitised and capped before it is held (a value that is not valid UTF-8 becomes `invalid`, and one over 255 bytes is cut at a character boundary). New settings `notify_pending_max` (default 10000, valid range 1 to 1000000, not present in any shipped `sys.config`; a value outside the range or not an integer falls back to the default with a WARN that names the key; see "Upstream client tuning" in [gateway.md](gateway.md)); size it at least as large as the largest `Subscribe` burst you expect; and `notify_probe_timeout_ms` (default 15000, valid range 100 to 300000, not present in any shipped `sys.config`, same fallback rule), the gateway's own deadline for the half-open notification probe: a probe worker that has not reported by then is killed and the probe fails like any failed probe. The other behaviour changes of the same restart are listed in the upgrade note below the table. Metrics: new gauges `yuzu_gw_upstream_notify_pending` and `yuzu_gw_upstream_notify_inflight` and counter `yuzu_gw_upstream_notify_coalesced_total`. The `reason` label of `yuzu_gw_upstream_notify_dropped_total` is now the closed set `at_capacity` and `unknown`: the value `circuit_open` is retired, so during a rolling upgrade old nodes still export `circuit_open` and new nodes export `at_capacity`, and a rule or dashboard that sums the family sees both. A rule or panel of your own that selects `reason="circuit_open"` stops matching once every node is upgraded: use `yuzu_gw_upstream_notify_pending` for held notifications and `reason="at_capacity"` for lost ones. The rollback is the previous gateway release. A rollback is itself a gateway restart: it disconnects every agent the node holds and carries the same agent-reconnect cost as the upgrade (see "Upgrade day" and "Agent dependency" in [What happens when the server restarts](gateway.md#what-happens-when-the-server-restarts), and the released-agent caveat above), so weigh it against the problem you are fixing. It also brings back the earlier behaviours: notifications dropped at 10 in flight or with the breaker open, a request that the gateway's own validation or encoder rejected (or a server status that means the request itself was wrong) counted as an upstream failure that can open the breaker, and no `cluster_id` boot refusal. The pending store is memory only, so nothing persists and nothing needs to be cleaned up; the notifications held at that moment are lost, as they were dropped before. Runbook rows and the measured evidence: [Stream Status Notification](gateway.md#stream-status-notification) and the [evidence record](../security-reviews/gateway-notify-pending-store-2026-10-05.md). |
| 0.15.x (next) | 0.12.0 | 0.12.0 | **The plain-HTTP port answers the four health probes when HTTPS is on (#5906).** `GET`/`HEAD` on `/livez`, `/readyz`, `/health` and `/api/health` on the redirect port now return `200` (or `503` while the HTTPS listener is not serving, the server is draining, or Postgres is down) instead of `301`, in cleartext; every other request still redirects. Server restart only; see the section below. |
| 0.15.x (next) | 0.12.0 | 0.12.0 | **The built-in server certificate is re-issued once with a server identity URI (#6016).** Same root, same key, so existing `mgmt_peer_pins` stay valid and the gateway needs no action. The old certificate shows as revoked with reason `superseded` in the CA inventory and the next CRL (bookkeeping, not a compromise). New audit action `server.default_certs_server_identity_upgraded`, new gauge `yuzu_server_identity_uri_present`. See "Behaviour change: the built-in server certificate is re-issued once with a server identity URI". |
| 0.14.x | 0.12.0 | 0.12.0 | **Fleet visualization intra-cube edges (PR 8).** `/viz/fleet` now draws faint white lines (opacity `0.3`) inside each machine cube connecting process dots that are reciprocal ends of a loopback TCP socket (127.0.0.1 / ::1). Two operator-visible changes: (a) **wire shape** — `/api/v1/viz/fleet/topology` `schema_minor` bumps `1 → 2` and a new optional `dst_pid` field appears on `scope: local` connection edges. Renderers that ignore unknown keys per the contract see no break; strict-validating consumers pinned to `schema_minor == 1` should relax their validator to `minimum: 1`. (b) **dropped unmatched halves** — unpaired Local-scope edges (kernel snapshot race during teardown, agent's 4096-connection cap cutting a partner) are now dropped server-side before serialisation. Integrations counting `connections` array length per machine as a proxy for active IPC pairs should re-baseline after upgrade; the count trends marginally lower. Lines appear only when the host has active loopback flows (e.g. Prometheus scraping node_exporter, a client talking to local Redis / Postgres); a fresh agent with no inter-process loopback shows process dots but no lines — expected, not a regression. **Windows agent (#5196):** set update-signing options in the `YuzuAgent` service's `Environment` registry value, not its binary path. Every installer run rewrites the binary path and silently drops them, and uninstalling deletes the `Environment` value, so a deployment that uninstalls first must set it again (*Windows: the service's `Environment` value* in `server-admin.md`). Agent installers from 0.14.0-rc1 to rc5 also stop with exit code 7 wherever PowerShell runs in Constrained Language Mode; use this release's. **Before upgrading Windows agents:** this installer stops with exit code 7, naming the reason in its `/LOG=` file, if `C:\ProgramData\Yuzu\agent-certs` exists but is not secured (for example a folder created or pre-staged by hand, or one a Group Policy adds permissions to), if a file in it is not owned by Administrators or SYSTEM, or if it or anything in it is a junction, symbolic link, hard link or subdirectory (a backup subfolder, say). The agent service is left running when it stops. Provision the bundle after installing, by copying it in as an administrator. The trust-anchor procedure block in `server-admin.md` stops on the same conditions, naming the reason (and on a healthy or rc1–rc5 endpoint completes, repairing rc files, as long as each file in it is owned by Administrators or SYSTEM; `icacls "<file>" /setowner *S-1-5-32-544 /L` fixes one you placed yourself): run it on a few endpoints first, and pilot the upgrade before a fleet-wide push. **Linux native packages need a recent distribution:** the server needs Ubuntu 26.04 or Fedora 42 class, the agent Ubuntu 24.04 class or newer; Ubuntu 22.04, Debian 12 and RHEL/Rocky 9 are not supported by the native packages. Check before upgrading older hosts, or use the container images (*Supported Platforms* in the user manual README, #5143). |
| 0.13.x | 0.12.0 | 0.12.0 | **Fleet visualization process layer.** `/viz/fleet` now renders interior process dots inside each machine cube, coloured by category (system/browser/database/web/runtime/other) — no operator action required, but operators upgrading from a 0.12.x build will see the dashboard suddenly populated with thousands of small spheres on next page load. Process data was already collected via `tar.fleet_snapshot` since 0.12.x; PR 7 only renders it. To suppress process visibility for specific agents (privacy-sensitive hosts, regulated workloads), set `process_enabled=false` on those agents via `tar.configure` — this also suppresses their dots on the visualization. Hover a dot to see pid/name/user/category; agent-controlled string fields are HTML-escaped and length-clamped before render. Per-cube dot count is soft-capped at 1000 for graceful degradation on heavily-threaded hosts; the cube tooltip still shows the true reported count. |
| 0.12.x | 0.12.0 | 0.12.0 | **Build-time content auto-import.** All YAML files in `content/definitions/` (217 InstructionDefinitions) and `content/packs/` (10 InstructionSets at this version) are now embedded in the server binary and auto-imported on every startup. Existing operator-customised definitions with matching IDs are NEVER overwritten — conflicts are silently skipped. **Behaviour change for upgrades:** definitions that an operator previously DELETED via the REST API or dashboard will reappear after upgrade because the auto-import treats a missing row as "needs creation". To permanently suppress a shipped definition, set `enabled: false` via the dashboard or `PATCH /api/v1/definitions/{id}` rather than DELETE-ing the row. Each auto-import write emits an `audit_events.action="content.bundled_import"` row with `principal=system` so operators can audit which definitions were inserted at boot. **Yuzu dark navy palette + Inter webfont** (visual change every operator sees) and **Apache ECharts chart renderer** (replaces bespoke SVG; same payload contract — no operator migration required) ship in the same release. |

**Rule of thumb:** agents and gateway should be the same minor version as the server, or one minor version behind. The server is always upgraded first. Upgrading the server first restarts it while gateways stay connected. A gateway at this version re-registers the sessions the server reports unknown, so a server-only restart recovers without operator action once both sides are upgraded; see [What happens when the server restarts](gateway.md#what-happens-when-the-server-restarts). Behind a gateway that does not yet read that report (which includes the server restart that ships this fix, because the server is upgraded first; restart the gateway after upgrading it, and read the next sentence first), agents can read offline after a server restart (observed on one local rig after a SIGKILL restart; graceful upgrade restarts were not tested), and dispatch worked only for the remaining route lease (up to about 90 s). A gateway restart disconnects every agent that gateway holds, and the agent then has to register again by itself: in a graceful gateway restart test, released v0.13.0 and v0.14.0-rc6 agents with default settings stayed wedged and v0.12.0 never re-registered (bug #2182, fixed by #5183, which is in no release tag yet), while a build with the fix re-registered in 11 to 12 s. Upgrade the agents to a build that includes #5183 before the gateway restart where you have one, or expect to restart the agent service on the released agents behind it; see "Agent dependency" in [What happens when the server restarts](gateway.md#what-happens-when-the-server-restarts).

## Behaviour change: new Crypto page, REST routes and MCP tools are reachable with `Inventory:Read`

**What changed.** The server adds the **Posture > Crypto** page (`/crypto`), two REST routes
(`GET /api/v1/crypto/libraries` and `/api/v1/crypto/libraries/devices`) and two MCP tools
(`get_crypto_libraries`, `list_crypto_library_devices`). This release also adds a CycloneDX 1.7 export of the same data
(`GET /api/v1/crypto/cbom` and the MCP tool `export_crypto_cbom`), also reachable with `Inventory:Read` alone. All of them are gated by
`Inventory:Read` alone, so any custom role that already holds `Inventory:Read` now reaches them.

- **Same data as `/software`.** The page reads the installed-software inventory the `/software`
  and `/inventory` pages already show, matched by package name; it adds no collection and no
  agent change. It names the devices carrying each library family, so the exposure is the one
  `Inventory:Read` already granted, in a new shape.
- **RBAC-off default.** While RBAC enforcement is off (the default) every authenticated session
  can read it, as with the other inventory reads. A service-scoped API token is refused with a
  `403` until RBAC enforcement is on.
- **Confinement applies.** A management-group-confined caller sees counts over its visible
  devices only.
- **`table_version` 3.** Every response carries `table_version`, the revision of the curated
  package-name table ([The library table](crypto.md#the-library-table)). Windows installer builds
  of OpenSSL are not matched by this table. A device-drill cursor is bound to the table version,
  and records the names source (`names_source` / `names_as_of`): a walk that straddles an upgrade, or one whose
  previous page was read on live names when the catalogue is now in use (a new or upgraded server
  whose catalogue becomes fresh mid-walk), gets a `400` and restarts without a cursor. The restarted
  walk is on the catalogue; the refusal can recur only if the catalogue goes stale and recovers
  during a walk.
- **Admission cap, per server process.** Each server process runs at most two `/crypto` store
  reads at once (the summary and the drill share the bound; N replicas allow 2N). A read over the
  bound is refused at once with a `503` (`crypto read capacity in use; retry`) carrying
  `retry_after_ms`, counted as `yuzu_inventory_read_degrade_total{reason="admission_full"}`.
  Clients that fan out `list_crypto_library_devices` calls should serialise them. A read that
  fails in the inventory store is a different `503` (`crypto library read degraded`).
- **Where the package names come from.** Responses carry `names_source` (`catalogue` or `live`)
  and `names_as_of` (epoch seconds, `null` when live). While the hourly software-catalogue refresh
  is fresh (at most two hours old) the names come from it, so a package name first reported after
  the refresh appears after the next one; otherwise, including on a new or upgraded server whose
  catalogue has not been built yet, the names are read live and the answer is current. Counts and
  versions are live either way. The live read takes about 1.7 to 2.2 s (summary) at 15M rows with
  30,000 names, and on a fleet above about 140,000 to 180,000 distinct package names with a stale
  catalogue it can pass its 5 s bound and answer `503`; see
  [Crypto](crypto.md#how-fresh-the-package-names-are).
- **Large fleets.** Fleets above about 2.7M installed-package rows (roughly 6,000 endpoints at
  about 450 packages each, about 1,800 at 1,500): the hourly catalogue does not build, so
  `/crypto` reads names live on every call (about 2 s per summary at 15M rows / 30,000 distinct
  names) and, with many replicas on one database, can time out. See
  [Scale](crypto.md#scale).

**Action.** None required. To keep a custom role out of the new surface, remove `Inventory:Read`
from it. Rolling back removes the page, routes and tools; nothing is migrated.

## Behaviour change: the built-in server certificate is re-issued once with a server identity URI (#6016)

On first boot after the upgrade, an install that uses the built-in default certificates has `default-server.pem` re-issued once, under the **same root and the same key**, with one added Subject Alternative Name: the server identity `yuzu://<ca-fingerprint>/server`. The previous certificate then appears **revoked with reason `superseded`** in the CA inventory (`GET /api/v1/ca/issued`, the CA page) and in the next CRL. That is bookkeeping, not a key compromise: the new certificate certifies the same key. Existing `mgmt_peer_pins` entries stay valid because the key is unchanged, so the gateway needs no action. The one-time event is audited as `server.default_certs_server_identity_upgraded` and logged as a WARN line. The CRL carries no revocation reason code, so the `superseded` reason is visible in the CA inventory only; a CRL consumer sees an ordinary revoked serial.

This release only mints the identity; the gateway management plane still admits the server by key pin. Check `yuzu_server_identity_uri_present` (`1` once `default-server.pem` carries the URI; it describes the file, so it is a readiness signal only when the agent and management listeners use the built-in certificates). Operator-supplied certificates, `--no-default-certs` and `--mgmt-tls-server-*` are not touched, and rolling back is safe (an older build ignores the extra name).

If you had **already revoked** the built-in server certificate for another reason (for example a suspected key leak) and not replaced it, the upgrade is skipped on purpose, with a warning on every boot and `yuzu_server_identity_uri_present` at `0`: re-certifying a key you withdrew would undo your revocation. Replace the key first by re-keying the set (see `--cert-san` in [Server administration](server-admin.md): renaming `default-marker.json` aside re-mints every default leaf with a new key, which also changes the server key every gateway `mgmt_peer_pins` entry refers to, so update those pins at the same time). The same warning and `0` appear while the certificate directory is read-only or the certificate authority key is not in it; if that is intentional the warning is harmless, and the identity appears the first boot the directory is writable. The same applies if the revocation lands while the upgrade is running: the new certificate is then revoked too (audit detail `replacement_withdrawn=true`) and the set must be re-keyed.

## Behaviour change: the Security and sign-in page (single sign-on, two-factor, HTTPS and agent mTLS)

Settings gains a **Security and sign-in** page (`/settings/security`, administrators only). It hosts the same four panels that `/settings` already loads, so no route, field name or audit row changes and `/settings` keeps working. What an operator or script can notice:

- **Saving SSO trims whitespace.** `POST /api/settings/oidc` trims leading and trailing whitespace from `issuer`, `client_id`, `redirect_uri` and `admin_group` before validating and storing them. A value saved earlier with a trailing space is stored as typed until it is saved again; a trailing space in the admin group previously made the group match fail for every SSO administrator at the next sign-in.
- **The mTLS switch toast no longer says "saved".** The switch changes only the value this server reports; it is not saved and start-up flags decide. Anything that matched the old toast text should be updated.
- **Errors appear inside the panel.** A failed SSO save or a rejected certificate paste is now shown in the panel on the new page instead of being dropped. The HTTP statuses are unchanged; the error text now sits inside the panel markup instead of an out-of-band span.
- **The panel is renamed.** "Multi-Factor Authentication" is now **Two-factor sign-in**, found under Settings → Security and sign-in. The `/fragments/settings/mfa` route is unchanged. The elevation error text for an account with no enrolled second factor names the new location.

## Behaviour change: dashboard API-token create and revoke apply MFA step-up

`POST /api/settings/api-tokens` and `DELETE /api/settings/api-tokens/{id}` (the Settings page's
API-token Create and Revoke buttons) now apply the same step-up check as the REST token routes.

- **SAML sessions** cannot satisfy the check and get `403` on both routes, as they already do on
  `/api/v1/tokens`. A deployment whose only interactive sign-in is SAML (`--auth-mode=sso-only`)
  therefore has no Settings-page route to create or revoke tokens. Create or revoke them from an
  API-token or MCP caller (the step-up check does not apply to those), or sign in with the armed
  break-glass account and create or revoke within `--mfa-step-up-window-secs` of that sign-in (the
  account is MFA-enrolled, so it is gated like any other local account, and it must hold an
  administrator role). If a deployment has neither an existing token nor a usable break-glass
  account, the only remaining route is to restart with `--mfa-step-up-window-secs 0` as a
  temporary measure: it disables the step-up check on every gated endpoint, not only these two
  (see [Authentication](authentication.md)), so restore the window afterwards.
- **OIDC sessions** are gated only when the identity provider attests MFA (`amr`) or
  `--mfa-enforcement` protects the role.
- **Local MFA-enrolled operators** whose proof is older than `--mfa-step-up-window-secs` must sign
  in again before creating or revoking a token. The Settings page cannot yet prompt for the code,
  so the button shows an error toast ("MFA step-up required") until the operator re-authenticates.
- With no MFA enrolled and no SAML sign-in, nothing changes.

## Behaviour change: web UI wording and layout (Console, Home after sign-in, hidden quarantine controls)

- **"Dashboard" is now "Console".** The navigation item, the Home tile, the page title,
  the "back to" links and the related Settings labels use the new name. Routes
  (`/`, `/fragments/dashboard/...`), API paths, MCP tool names and permission names are
  unchanged, so bookmarks and scripts keep working. Prose elsewhere in this manual still
  says "dashboard" for the web UI as a whole.
- **Home lists the screens only after sign-in.** Signed out, `/home` shows the sign-in
  form and nothing else; the fifteen screen tiles appear once you are signed in. Health
  probes that fetch `/home` still receive `200`.
- **The Hardware pages no longer show quarantine controls.** The Quarantine link, the
  Quarantined pill, the Quarantined devices panel, the containment banner and tab, and the
  quarantine plugin's rows in the Actions lens are hidden until an approval workflow for containment actions is added. Quarantine itself is unchanged: the REST API, the MCP tools, the quarantine
  plugin and the role-gated quarantine instructions on the Instructions page all work as
  before, and server-side enforcement does not depend on the UI. While the controls are
  hidden, use `GET /api/v1/quarantine` to list records. `DELETE /api/v1/quarantine/{agent_id}`
  ends the server record only; to remove the device's firewall rules, run the quarantine
  plugin's release instruction (`security.quarantine.release`, "Release Device from Quarantine")
  from the Instructions page (or through `execute_instruction`) and confirm with the
  status instruction. No configuration change is needed.
- **Colour schemes.** Settings > General > Appearance now offers six schemes (Slate stays
  the default). The choice is stored in the browser, not on the server.

## Behaviour change: the Groups and enrolment page; the Settings enrolment panels look and act differently

- **New page: Estate > Groups and enrolment** (`/groups`). It hosts the agent approval queue, the auto-approve rules and the enrolment tokens on one page. Management groups stay in Settings. The page opens for every signed-in user; the three panels need the Administrator account role, as they did in Settings, and a user without it sees "Not available to your account" in each panel.
- **The Settings panels use the same renderers**, so they change too (**Enrollment Tokens**, **Pending Agent Approvals**, **Auto-Approve Policies**). Routes, element ids, form fields and the Administrator decision are unchanged, so a script that calls these routes still reaches them. Two behaviours differ for such scripts (a stale approve or deny, and a stale rule action, now answer `409`; see below). The one difference in the gate is audit: a refused browser session on the three auto-loading panels no longer writes an `auth.admin_required` row per panel per view (a refused token, and every refused write, still does). What you will see:
  - Token **Expires** is shown in UTC (it was raw epoch seconds). The status (**Active**, **Expired**, **Exhausted** or **Revoked**, as before) is now a pill, and active tokens are listed first. The token reveal has a **Done** button.
  - The approval queue shows when each agent asked to join (UTC) and gains **Forget**, which removes a waiting request (the agent is queued again the next time it asks to join). **Approve all** and **Deny all** replace the two-click buttons with a confirmation that gives the total and the first ten hostnames, and are disabled while the list shows only part of the queue.
  - Auto-approve rules are described by what they match (hostname and cloud provider are agent-reported and not verified; address rules are IPv4 only; a CA fingerprint rule is marked as never matching at this release). The match mode is two buttons that each ask for confirmation, where it was a drop-down that applied at once. Enable and Add rule now ask for confirmation too, and Remove (which already asked) names the rule. Disable asks only in "all must match" mode, where it normally widens admission; for the last enabled rule it warns that no agent will be approved automatically until a rule is enabled. A rule that matches every agent is flagged **Matches every agent**.
  - Each list shows at most 200 rows; the token and waiting-agent panels say how many are not shown.
  - **Approve and Deny act only on an agent that is still waiting.** A request for an agent that was already approved or denied now answers `409` with the refreshed list and an error message; before, a stale Approve silently reversed a denial and a stale Deny turned an enrolled agent into a denied one. Scripts that approve an agent twice now get `409`, and so does a script that approves a denied agent to re-admit it: that used to work only because the store applied the decision without checking the row's status, and was never a supported recovery. A denial is permanent for that agent id, and there is no reinstate action today. A machine denied by mistake has to register as a new agent: reinstall it or wipe its agent data directory (a different `--agent-id` alone is not enough where client certificates are required), and remove or tighten any token or auto-approve rule that would admit it again; see [Agent enrollment](server-admin.md#agent-enrollment) and [Device Management](device-management.md#tier-1-manual-approval).
  - **Rule Enable, Disable and Remove check the rule they were drawn for.** The dashboard now sends the rule's type and value (and, for a toggle, its state) with the request, and a request for a rule that moved, changed or was removed since the list loaded answers `409` with the refreshed list. Scripts that address a rule by position alone are unchanged.
  - **Audit strings changed.** If a SIEM rule keys on them: `enrollment.auto_approve.rule_toggle` detail is now `type=<t> value=<v> enabled=<0|1> by=<operator>` (it was `enabled=<0|1> by=<operator>`); `enrollment.auto_approve.rule_remove` detail gains `type=` (`type=<t> value=<v> label=<l> by=<operator>`); and there are new refusal details with `result=denied`, `stale_rule_view` on rule toggle and remove and `refused_wrong_status` on approve and deny. `rule_not_found` also now accompanies a `409` when a dashboard request names a rule whose position is gone (it was only a `200` no-op). See [Audit Log](audit-log.md).
  - The token and pending fragments, and the responses that mint tokens, carry `Cache-Control: no-store, private` and `Vary: Cookie`, so a proxy or the browser cache no longer keeps them. The re-rendered list that revoke, approve, deny, forget and the bulk actions return does not carry them.
- No setting, migration or action is needed. Rolling back restores the earlier panels.

## Behaviour change: the plain-HTTP port answers the four health probes when HTTPS is on (#5906)

**What changed.** With HTTPS on, `GET` and `HEAD` on `/livez`, `/readyz`, `/health` and `/api/health` on the redirect port (`--web-port`, `8080` by default) now return the probe's answer instead of `301`: `200`, or `503` while the HTTPS listener is not bound or has exited (`https_listener_not_serving`), the server is draining, or Postgres is down. Every other request on that port still redirects. The bodies are the unauthenticated ones the HTTPS port already served, now also readable in cleartext on this port (version, store names, `agents.online` and the `tls` block). `--no-https-redirect` removes the listener.

**What to check.**

- A monitor that expected `301` on the plain port, or followed it to the TLS listener, now sees a probe answer. Point it at `https://<host>:8443/readyz`, or run `yuzu-server --healthcheck` in the container.
- A Kubernetes `httpGet` probe on the plain port keeps working but now reads the plain port's own answer (for `/livez`, `503` only while the HTTPS listener is not bound or has exited; `/readyz` also answers `503` while draining or when Postgres is down). The kubelet used to follow the `301` to the TLS listener (same host name, port ignored), so a wedged HTTPS listener failed the probe; for TLS-listener liveness use `httpGet` with `scheme: HTTPS` on 8443, or the `exec` probe. A probe with a custom `Host` header never followed the redirect and now sees real `503`s.
- Port 8080 now serves health data without encryption or authentication. Publish it only to the orchestrator network, or set `--no-https-redirect`. `--web-address 127.0.0.1` binds the HTTPS dashboard to loopback too, so it does not restrict only the plain port.
- Responses on the plain port (the `301`s, `400`s and probe answers) now count in `yuzu_http_requests_total` with their own method and status labels, so request-rate totals and the 5xx error ratio include them; a plain-port `503` while the HTTPS listener is down is counted, but while that listener is down plain `/metrics` is itself a `301` to it, and the listener binds once per process, so recovery is a restart that resets the counter: those `503`s never reach an error-ratio alert such as the example `YuzuHighErrorRate`. Use `--healthcheck` or `up == 0` to catch that state.
- That port's responses now carry the same security headers as the HTTPS port, minus HSTS and the CSP `upgrade-insecure-requests` directive. Its worker pool is fixed-size (at most 64 threads, created at boot), and shutdown waits at most 15 s for its thread.
- Images built before this change are unchanged: they redirect, and have no `--healthcheck`.

## Behaviour change: new agent, policy and fragment identifiers are restricted; page links encode identifiers

- A `Register` (direct or through the gateway) with an agent id the server has not seen before is now refused with `INVALID_ARGUMENT` unless the id uses only letters, digits, `.`, `_`, `:` and `-` and is not only dots (counted in `yuzu_register_invalid_agent_id_total{reason="charset"}`). Agents that are already enrolled, pending or denied are not affected, and the agent's own generated UUID always passes. If you set `--agent-id` or `YUZU_AGENT_ID` to a value with other characters (for example `DOMAIN\HOST`, `user@host` or a space), change it before the agent first registers. An agent whose enrollment row no longer exists is treated as new again: a pending row an administrator removed, or an enrollment store restored from an older backup, reset or rebuilt. Such an agent, if its id has other characters, gets the refusal on every attempt (retrying with backoff up to 300 seconds) until you change its `--agent-id` / `YUZU_AGENT_ID` to a conforming value. Through the gateway the agent sees the server message wrapped in an `INTERNAL` status. Before upgrading, check any explicit agent ids you set against the rule.
- A `Register` (direct or through the gateway) with an agent id that contains a NUL byte, a control byte or `,` is refused and counted in `yuzu_register_invalid_agent_id_total{reason="nul"}` or `{reason="control"}`; no agent started with a conforming id produces either. A direct agent sees `INVALID_ARGUMENT`; an agent connecting through the gateway sees `INTERNAL` with a message that starts `Upstream registration failed`, as the charset bullet above notes. An id with a NUL byte or a control byte or `,` was already refused with `INVALID_ARGUMENT`, but it was logged as an enrollment store failure; the NUL refusal now has its own count and message and is decided before the enrollment store is read, so it also answers `INVALID_ARGUMENT` rather than `UNAVAILABLE` while no enrollment store is attached. The custom-properties `PUT` and `DELETE` routes likewise refuse an agent id that is empty, contains a NUL byte or is over 256 bytes, and the `GET` route answers empty for one.
- The registration-path log lines now print agent ids and hostnames folded: spaces, `=`, `,` and non-ASCII bytes are shown as `_` and long values are shortened. The "Agent registered" line quotes the hostname. An id with a control byte or `,` is now logged at warn level and counted (`reason="control"`) instead of as an error-level `enrollment status read failed` line, so adjust any log alert that matches that text. A legacy id such as `my host` therefore appears as `my_host` on the registration lines but as stored on the Heartbeat, Subscribe and registry lines, so one log can hold two spellings of the same id. The section on the new `Guardian T_*` diagnostic log lines in [server-admin.md](server-admin.md) lists which lines fold and which print as stored.
- A new policy or policy fragment with an explicit `id` must use letters, digits, `.`, `_` and `-` (up to 128 characters) and not only dots, the same rule instruction definitions use. Existing records are not changed.
- Dashboard links and actions that carry an agent, policy or update-package identifier now percent-encode it. A row whose identifier is empty, `.` or `..` is shown without actions, and the pending-agent approve, deny and remove routes answer `400` for such an identifier.

## Behaviour change: the Settings link follows the server's own admin decision (#5779, #4208)

`GET /api/me` and `GET /api/v1/me` now report `effective_role`, `elevated`,
`elevated_until` (only while elevated) and `can_access_settings`, and the shell
shows the Settings entry only when `can_access_settings` is `true`. Users with an
active just-in-time elevation now see the link; RBAC PlatformEngineer or
`Administrator`-label holders who are not legacy admins no longer see a link that
redirected away. During a rolling upgrade an older replica omits the new keys, so
the Settings link is hidden for every user, administrators included, whenever
`/api/me` is answered by an older replica; open `/settings` directly by URL (it is
unaffected) or wait for the upgrade to finish. Tabs opened before the upgrade keep
the old shell until reloaded. No configuration change is needed.

## ⚠️ Breaking: the audit log is admin-only while RBAC is off, and audit reads are bounded (#5771)

**Audit trail access.** With role-based access control switched off (the shipped
default), only administrators can now read the audit log. A non-admin signed-in
user or API token gets `403` on `GET /api/audit`, `GET /api/v1/audit`,
`GET /api/v1/audit/auth-sample`, `GET /api/v1/engine-principals/audit/no-admin`,
the MCP tools `query_audit_log` and `audit_engine_no_admin`, and the
`yuzu://audit/recent` resource. Previously any signed-in user could read it.
To give a non-admin the trail, enable RBAC and assign a role that holds
`AuditLog:Read`. Admins and RBAC-enabled `AuditLog:Read` holders are unchanged.

**Find what broke.** Denials are audited and counted. As an admin, run
`GET /api/v1/audit?action=auth.permission_required&since=<upgrade epoch>&limit=1000`
and read `principal` on the rows whose `detail` begins
`topology floor: non-admin role denied AuditLog:Read`. Alert on
`sum(yuzu_auth_topology_floor_denied_total{permission="AuditLog:Read"}) > 0`. A
poller that treats `403` as "no new events" stops collecting evidence silently,
so make evidence collectors fail loudly on any non-200.

**Two ways to restore access.** (1) Enable RBAC and assign a role holding
`AuditLog:Read`; read [Enabling RBAC](rbac.md#enabling-rbac) first, because a user
with no management-group role then sees no agents. (2) Run the collector on an
admin-owned token; while RBAC is off that token carries full admin authority, so
prefer (1) for evidence collectors.

**Rolling upgrade.** An older replica still serves the trail to non-admins until
every replica is upgraded.

**Bounded audit reads.** `GET /api/audit` now clamps `limit` to 1000 and returns
`400` for an `offset` above 10000, matching `GET /api/v1/audit` and the MCP tool.
Callers that paged deeper or asked for more than 1000 rows should narrow the
window with `since`/`until`. MCP `query_audit_log` now rejects a wrong-typed or
negative filter with an invalid-params error (`-32602`) instead of silently
ignoring it.
`query_audit_log` string filters are now limited to 1024 characters and a longer value is `-32602`. `GET /api/audit` and `GET /api/v1/audit` return `400` for a NUL or invalid UTF-8 in a string filter (a NUL used to truncate the filter and widen the read), and `GET /api/audit` also returns `400` for a negative `since`/`until` or an inverted window. `query_audit_log` now returns `has_more` beside `entries` in its structured result; the text channel is unchanged. During a rolling upgrade an older replica omits `has_more`, so a client that validates `structuredContent` against the new output schema can fail against it until every replica is upgraded. Clients that sent such filters should shorten or drop them.

**Role reads fail closed.** `GET /api/v1/rbac/roles` and
`GET /api/v1/rbac/roles/{role}/permissions` now answer `503` when the permission
store is degraded (previously an empty `200`) and `404` for an unknown role
(previously `200 {"data":[]}`).

## Behaviour change: `POST /api/v1/hardware/{id}/sync` refuses cross-site cookie writes

**What changed.** A call to `POST /api/v1/hardware/{id}/sync` (and the new fleet form `POST /api/v1/hardware/sync`) authorised by a **session cookie** must carry an `Origin` or `Referer` header naming this site (or an entry from `--csrf-trusted-origin`), otherwise it answers `403 cross-site request refused` and is audited as `csrf.denied`. API, MCP and engine token callers are not affected.

**What to check.** A script that signs in with a cookie and calls the per-device sync route without `Origin` or `Referer` now gets `403`: use an API token, or send the header. The Hardware and Software pages already send it. Behind a reverse proxy that rewrites `Host`, declare the public address with `--csrf-trusted-origin`.

## Behaviour change: adding, removing and re-roling a local account refuse cross-site cookie writes and are audit-first

**What changed.**

- `POST /api/settings/users`, `DELETE /api/settings/users/{username}` and `POST /api/settings/users/{username}/role` called with a **session cookie** must carry an `Origin` or `Referer` header naming this site (or an entry from `--csrf-trusted-origin`), otherwise they answer `403 cross-site request refused` and write a `csrf.denied` audit row. Calls authorised by an API token are not affected.
- `POST /api/settings/users/{username}/role` accepts only `application/json` and answers `415` otherwise.
- Each of the three writes a `result=attempted` audit row before it changes anything. If that row cannot be written the call answers `503` with `Sec-Audit-Failed: true` and changes nothing; if only the outcome row is lost the `2xx` stands and the header is set.

**What to check.** A script that signs in with a cookie and calls these routes without `Origin` or `Referer`, or posts the role body as a form, now gets `403` or `415`: use an API token, send the header, or post JSON. A SIEM or alert rule that counts `csrf.denied` rows will now see the three user-management routes as targets, and a rule on `user.create`, `user.delete` or `user.role_change` rows will now also see `attempted` rows.

## Behaviour change: MCP `revoke_upload_grant` is audit-first and refuses during an audit-store outage (#6169)

**What changed.** The MCP tool `revoke_upload_grant` now writes an `upload_grant.revoke` audit row with result `attempted` before it revokes anything, then a `success` or `failure` row, the same rows its REST twin `DELETE /api/v1/upload-grants/{grant_id}` writes. If the `attempted` row cannot be stored, the tool answers a retryable `-32603` error carrying `retry_after_ms` and the grant is **not** revoked. It stays redeemable until it expires at its TTL. The REST route already refused the same way, with `503`, so no transport can revoke a grant while the audit store is down. The success result no longer includes `audit_persisted`. `mint_upload_grant` is unchanged.

**What to check.** An MCP client that treated `revoke_upload_grant` as always succeeding while the grant store is up must handle the retryable error: retry after `retry_after_ms`, and on the supervised tier request a fresh approval, because the refused call consumed its ticket. A client that read `audit_persisted` from this tool must stop. A SIEM or alert rule that counts one `upload_grant.revoke` row per revoke now sees two (`attempted`, then the outcome), so match on `result=success`. An `attempted` row with no outcome row for the same `target_id` means the outcome is unknown: check the grant's state with `list_upload_grants`.

## Behaviour change: `PUT /api/config/{key}` is audit-first, refuses cross-site cookie writes and floors `heartbeat_timeout` at 30 seconds

**What changed.**

- A call to `PUT /api/config/{key}` now writes a `config.update` audit row with result `attempted` before it changes anything, then a `success` or `failure` row. Each accepted call leaves two rows where it left one. If the `attempted` row cannot be stored the call answers `503` with `Sec-Audit-Failed: true` and nothing is changed, so a runtime setting (including the log level) cannot be changed during an audit-store outage.
- A call authorised by a **session cookie** must carry an `Origin` or `Referer` header naming this site (or an entry from `--csrf-trusted-origin`), otherwise it answers `403 cross-site request refused` and is audited as `csrf.denied`. API, MCP and engine token callers are not affected.
- `heartbeat_timeout` below 30 seconds is refused with `400`. A value below 30 that an earlier build stored is raised to 30 when the server starts (a WARN line names it); `GET /api/config` keeps listing the stored override until you `PUT` a value of 30 or more.

**What to check.** A script that signs in with a cookie and calls this route without `Origin` or `Referer` now gets `403`: use an API token, or send the header. A SIEM or alert rule that counts one `config.update` row per change now sees two; match on `result=success`. Behind a reverse proxy that rewrites `Host`, declare the public address with `--csrf-trusted-origin` or the General page's Save is refused. A stored value below 30 cannot be cleared by saving 30 on the General page, because that page already shows 30 as the current value: save another value first, or `PUT` it with a token. The Developer page's fragments are now administrators only (a non-admin holding `Infrastructure:Read` gets `403` from them), and the permission grid no longer writes a denial row on each load. Whatever you set, keep `heartbeat_timeout` well above the heartbeat interval your agents run with: 30 leaves no margin for a late heartbeat.

## ⚠️ Breaking: OIDC refuses RSA signing keys under 2048 bits or with a degenerate exponent (#1901, #6058)

OIDC sign-in no longer accepts an RSA signing key whose modulus is under 2048 bits, or whose public
exponent is below 3, even, or wider than 32 bits (65537 is the near-universal choice). Such a key is
skipped when the IdP's key set is parsed, with the warning
`OidcProvider: failed to parse JWK kid=<kid> (RSA modulus under 2048 bits)` (or `(RSA exponent is 1)`,
`(RSA exponent is even)`, `(RSA exponent over 32 bits)`), and its siblings are kept.

- **Who is affected.** An IdP that signs ID tokens with such a key, for example a legacy, in-house or test
  IdP. That includes an IdP that also publishes a larger key it does not sign with. A token that names the
  skipped key's `kid` is refused with `no matching JWKS key found`; a token with no `kid` that the skipped
  key signed is refused as `token may be forged`; if every key the IdP
  serves is skipped, nobody can sign in. Settings Test Connection reports only the keys that remain, so it
  can be green while sign-ins fail: a count lower than the number of RSA signing keys the IdP publishes means keys
  were skipped.
- **Check before upgrading.** Fetch the IdP's `jwks_uri` and confirm that each RSA key it signs with has a
  modulus (`n`, base64url-decoded) of at least 2048 bits and an exponent (`e`) of 65537 or another odd value
  of 3 or more that fits in 32 bits.
- **`--auth-mode=sso-only`.** If every operator signs in through the IdP, a refused key locks them all out.
  Before upgrading, confirm a break-glass account is named and enrolled, and that you can run
  `yuzu-server --break-glass-arm` on the server host (see "Hardened auth mode" below); the local-password
  path does not use the OIDC callback.
- **Rollback.** There is no setting, flag or environment variable that lowers these checks; they are fixed
  in the server. Rolling back to the previous release accepts such keys again (a weaker posture) and needs no
  data change, because nothing is persisted. It is the recovery if you are locked out under `sso-only` with
  no armed break-glass account.

Also in this release (a fix, not a break): a token with no `kid` member is now checked against each usable
signing key of the IdP in turn, at most the first 16 in the order published, instead of only the first. An
IdP that omits `kid` while it publishes several signing keys, as it rotates, no longer has sign-ins refused
intermittently.

## Behaviour change: OIDC sign-in now requires the issuer's discovery document (#5692)

**What changed.** The server no longer derives the OIDC authorization and token endpoints from the issuer URL, and the JWKS location (`jwks_uri`) is no longer left empty. All three are read from `{issuer}/.well-known/openid-configuration` the first time a sign-in needs them. Before this change an IdP whose endpoints were not the derived ones (Keycloak, for one) answered the sign-in redirect with an HTTP 404 (the browser was redirected to an authorization URL the IdP does not serve), and every ID token failed signature verification because no JWKS was ever fetched. Both failed closed; both now work. Neither server start nor a Settings save contacts the IdP, so a bad issuer is not noticed until the first sign-in or until someone clicks "Test Connection" (a connectivity check; it is not a guarantee of what a sign-in will hit, see [Test Connection](authentication.md#oidc-single-sign-on)).

**No working sign-in can regress, but a previously green Test Connection can now be red.** In v0.13.0 and later, before this change, the server did not read `jwks_uri` from the issuer's discovery document, so ID token signatures could not be verified and sign-in failed closed. There is therefore no working sign-in to break in those releases. "Test Connection" is stricter now: it can turn red for an issuer that differs from the document's `issuer` by even a trailing slash, a document with no `jwks_uri`, an endpoint on a different scheme than the issuer, a JWKS that cannot be fetched or holds no usable key, or an address the egress policy refuses (see below). A green "Test Connection" before this change did not prove that sign-in worked. Rollback is a binary downgrade with no schema change, and it returns to the previous OIDC behavior, which cannot complete a sign-in: it does not restore a working one.

**Redirect URI.** The earlier manual said the Redirect URI was auto-computed when left blank; outside the startup-flag default (`http(s)://localhost:<port>/auth/callback`) that was never true, and a provider without one never fetches discovery. Behavior change: a Settings save (`POST /api/settings/oidc`) with a blank Redirect URI is now refused with `400`, a red message naming the field and an error toast, where before it was saved and `GET /auth/oidc/start` then answered `500`. Enter the callback URL registered at the IdP.

**Review a forgotten OIDC configuration before upgrading.** An OIDC configuration left in place but unused (in v0.13.0 and later, before this change it could not complete a sign-in, so nobody noticed) becomes a live sign-in on upgrade. If `--oidc-admin-group` is also set, members of that IdP group can now sign in as administrators. Check the flags and the group, or remove the flags.

**Breaking: an IdP on a private network now needs `--oidc-allow-private-networks`.** The server now refuses to make an OIDC request (discovery, the JWKS, Test Connection, the token POST) to a loopback, RFC 1918 (`10/8`, `172.16/12`, `192.168/16`), carrier-grade NAT (`100.64/10`) or IPv6 unique-local (`fc00::/7`) address unless it is started with `--oidc-allow-private-networks` (env `YUZU_OIDC_ALLOW_PRIVATE_NETWORKS`). This applies to the issuer host and equally to the hosts in the discovery document's `jwks_uri` and `token_endpoint`, which are checked when they are used. A self-hosted Keycloak or ADFS on an internal address, and a lab IdP on `localhost`, will fail with `request failed: address not permitted by the OIDC egress policy` (and Test Connection will show the same text) until you set the flag. Link-local addresses (including the cloud metadata address `169.254.169.254`), the listed cloud metadata addresses (`100.100.100.200`, `168.63.129.16`, `fd00:ec2::254`), multicast and unspecified addresses are NEVER allowed, with or without the flag; Oracle Cloud's `192.0.0.192` is the exception, because it lies in the `192.0.0.0/24` special-purpose block that the flag admits. The flag is a server start-up option only; it cannot be set from the dashboard or the REST API. Windows caveat: the token request is checked before WinHTTP resolves the name again, so a DNS change in between is not covered there, and a name whose answer mixes permitted and refused addresses is refused outright (WinHTTP cannot be pinned to the permitted one). Details: [authentication](authentication.md#network-and-trust).

**Breaking: plain `http://` to a public address is now refused, with no switch.** An OIDC request over `http://` (the issuer, or a discovery-document endpoint) whose target address is public is not made; the error is `request failed: plain http is not permitted to a public address` (`token endpoint request failed: ...` for the token POST), and Test Connection shows the same text. `https://` to a public address is unchanged. `http://` to a loopback, private, carrier-grade NAT or unique-local address still works, but only with `--oidc-allow-private-networks`, and it stays exposed to anyone on that network path: the signing keys, the token response and the client secret travel unencrypted there. If an IdP on a public address is configured with an `http://` issuer, change it to its `https://` URL.

**What to do.**

- **Network.** The server itself must reach the issuer host, and also the hosts in the document's `jwks_uri` and `token_endpoint`, which can differ from the issuer host, over HTTP(S) when someone signs in (and from "Test Connection"). The token endpoint was already server-side egress; the discovery and JWKS URLs are new. No HTTP(S) proxy is used on the discovery and JWKS path (the Windows token request uses the system default proxy), so a proxy-only egress needs a direct route to those hosts. Use an `https` issuer: the JWKS is the trust root for every ID token and the client secret is sent to the token endpoint, both over the issuer's scheme, so an `http://` issuer on a non-loopback host lets anyone on the network path forge a sign-in (the server logs a warning; an `http://` issuer on a public address is refused outright, and on a private address it needs `--oidc-allow-private-networks` and stays exposed to that network path). `--oidc-skip-tls-verify` now also governs discovery and JWKS (the Windows token request ignores it), and a private CA must be in the server's operating-system trust store.
- **JWKS per sign-in.** Every sign-in now makes one request to the IdP's `jwks_uri` (nothing is cached, so a key the IdP withdraws stops verifying at the next sign-in). Check that your IdP's published rate limit for that endpoint covers your peak sign-in rate: a 429 or 5xx logs `OidcProvider: JWKS fetch failed: HTTP <status>` and fails that sign-in with `sso_failed`, with no retry. Under `--auth-mode=sso-only` a JWKS outage locks out every operator who has no armed break-glass account, so confirm one is named and enrolled before upgrading (see Hardened auth mode); the local-password path does not use the OIDC callback. A sign-in holds one HTTP worker of the pool shared with the dashboard and REST for up to about 10 s while its JWKS request runs.
- **First login after a restart** pays one discovery round trip, and sign-ins that arrive during it are refused at once (retry in a moment). That state ends when the fetch returns, within the total bound (10 s by default: the 5 s per-operation timeout times 2). If sign-ins keep being refused this way with no cause line well past that, restart the server, which clears the in-flight state.
- **If discovery fails**, `GET /auth/oidc/start` answers `500` ("could not start the SSO sign-in flow") and no sign-in begins; a callback that cannot reach discovery or the JWKS is refused with the usual `sso_failed` redirect. A failed discovery is not retried for 30 seconds; the JWKS is fetched afresh on every sign-in, so a failed fetch is tried again at the next one. A sign-in that arrives while another is fetching discovery gets the same JSON `500` at once, with no cause line of its own, and succeeds when retried a moment later.
- **Time bounds.** Each discovery and JWKS request has 5 s per-operation timeouts and a total bound of 2 x that timeout (10 s by default) from the start of the request, covering name resolution (on Linux and macOS where the HTTP client library's non-blocking resolver is built in: true of the Linux build, not checked for macOS; on Windows the server cancels its own lookup at the per-operation timeout and then waits up to 5 s more for the canceled lookup to finish, and keeps one that still has not finished in a bounded ledger of 16 until it does, failing further lookups closed while the ledger is full), connect, the TLS handshake and the response. The token-exchange POST has per-operation timeouts only (10 s, 15 s, 15 s on Linux and macOS; the WinHTTP defaults on Windows) and no total bound; its response is capped at 256 KiB, and on Windows it does not follow redirects and accepts only HTTP status 200 (a 3xx fails the sign-in). "Test Connection" runs discovery and then the JWKS fetch one after the other, each with its own total bound, so one click can take up to about 20 s in the worst case (a slow discovery document followed by a stalled JWKS fetch); a dead IdP fails at the discovery step.
- **Descriptors.** On Linux and macOS a request also needs one spare file descriptor beyond its socket, reserved before the socket is opened: with none available it fails closed with `request failed: no file descriptor available`.
- **First checks.** Settings > "Test Connection" shows whether the server can fetch the discovery document and the signing keys for the issuer typed in the form; then read the server log line `OidcProvider: discovery failed for issuer <issuer>: <reason>`. See [OIDC sign-in fails](authentication.md#oidc-sign-in-fails) for the log lines and what each means.
- **Monitoring.** A discovery failure at `/auth/oidc/start` is logged only (`OIDC auth flow could not start`), with no audit row and no counter (#5704); failed callbacks are audited as `auth.oidc_login_failed` and counted in `yuzu_auth_oidc_login_total{result="error"}`, and a callback's discovery or JWKS failure shares that generic row and counter. The log lines worth alerting on are listed under "Log lines to watch" in [OIDC sign-in fails](authentication.md#oidc-sign-in-fails).
- **If the IdP changes.** A successful discovery is kept for the lifetime of the provider. An IdP that moves its `jwks_uri` or endpoints needs a Settings save (which rebuilds the provider) or a server restart. Signing keys are fetched afresh for every sign-in and are not cached, so a key the IdP has retired or revoked stops verifying at the next sign-in (#1901 UP-19); the cost is one JWKS request per sign-in, and a JWKS endpoint that is down refuses every sign-in until it answers (there is no grace period for a previously fetched key). A token that names a `kid` the key set lacks is refused. A malformed key in a served set is skipped and its siblings are kept. Host names must be ASCII: give an internationalized name in its punycode (`xn--`) form.
- **The issuer must match byte for byte.** The configured issuer must match the discovery document's `issuer` and the tokens' `iss` byte for byte, including any trailing slash. Copy it from the IdP's discovery document. Every endpoint must be an absolute URL on the issuer's scheme (an `https` issuer whose document lists `http` endpoints is refused), at most 2048 bytes, with no fragment (a query is allowed and is kept; the authorization endpoint's query must not use the names of the OAuth request parameters Yuzu adds, and a token endpoint query is kept on every platform), with a plain `host[:port]` authority (an IPv4-mapped IPv6 literal such as `[::ffff:1.2.3.4]` is rejected on purpose: the HTTP client library cannot represent it); the configured issuer must not contain a query or fragment; the document must list all three of `authorization_endpoint`, `token_endpoint` and `jwks_uri`, and one missing is refused even when the step in progress would not use it.
- **Verified against Keycloak 26.4.0 (plain `http` and `https`, Linux); Entra not verified.** Microsoft Entra ID is supported by the standard but has not been verified end to end by the project. Use the tenant-ID issuer (`https://login.microsoftonline.com/<tenant-guid>/v2.0`) and the manual procedure in [authentication](authentication.md#manual-verification-against-a-real-idp).
- **Windows.** The token exchange uses WinHTTP; discovery and the JWKS fetch use the portable HTTP client from handler threads, which was once found failing there for `https` issuers. The tree has an `https` test from a handler thread, but a real `https` sign-in on a Windows server has not been verified by the project: test one before relying on it; a failure shows as the log lines above.
- **No operator override of the endpoints.** They come from the discovery document or not at all, so an air-gapped IdP that does not serve its discovery document cannot sign in. A Settings save does not wait for sign-ins in progress (one rare exception, see "Known limits"): they hold the OIDC lock only to pick up the current provider. A sign-in whose exchange finishes after a save replaced the provider is refused with `sso_failed` (audit reason `provider_replaced`) instead of being minted under the old admin group or issuer; a session that is already live is not revoked by a save. Every save rebuilds the provider, so users who are mid-sign-in must start again: save outside peak sign-in hours. The SIGTERM behavior while a token POST is stalled is under "Known limits". See "Known limits" in [authentication](authentication.md#known-limits).

## Behaviour change: sign-in moves to the landing page, `/login` redirects

**What changed.** `/home` is now the sign-in page (and the landing page for a signed-in user). A page requested
without a session is redirected to `/home?next=<screen key>` instead of `/login`, and `GET /login` answers
`302` to `/home`, forwarding only a valid screen key and a known SSO error code. `POST /login`, `/login/mfa`,
`/login/mfa/enroll`, the OIDC and SAML callbacks and the session cookie are unchanged. Signing in no longer
leaves the user on the Dashboard: password and single-sign-on sign-ins both end on `/home`, which offers an
"Open Dashboard" button. A request sent by htmx without a session now answers `401` with an `HX-Redirect: /home`
header rather than a redirect, so a panel never swaps the sign-in page into itself.

**What to check.** Any monitor, load-balancer health check or script that expects `GET /login` to answer `200`
must probe `/livez`, `/readyz`, `/health` or `/home` instead (`/home` answers `200` without a session). Scripts
that sign in with `POST /login` need no change. Bookmarks to `/login` keep working through the redirect.

## Behaviour change: Guardian heartbeat reconcile is admission-controlled and fails closed on a degraded tag or property store (#5513)

**What changed.** The heartbeat reconcile is the re-push the server sends to an agent that reports a policy generation behind the server's (see [Guaranteed State](guaranteed-state.md)). Three things differ from the previous release:

- **Admission control.** Each server replica now admits reconcile pushes against its own in-memory time budget and a soft in-flight cap of 256. A reconcile that is not admitted is **shed**: nothing is sent, no audit row is written, and the agent's 25 s per-agent slot is not consumed, so the agent retries on its next heartbeat. The per-agent limit itself is unchanged: one re-push per 25 s per agent.
- **Fail closed on a degraded scope read.** If the tag store or the custom-properties store cannot be read while the reconcile evaluates a rule's scope for the agent, the reconcile now **aborts** and sends nothing. Previously the unreadable store was treated as "agent not in scope", and the server pushed a rule set narrowed to exclude that rule, which disarmed the scoped rule on the agent until a later push restored it.
- **The agent refuses a lower-generation full push (#5611).** The agent binary now refuses a `full_sync` push labelled below the policy generation it holds (a push at the held generation is still applied). Agents on the previous release keep applying an older full push. If a server's generation counter ever falls below what its agents hold (for example after a database restore), upgraded agents refuse every full push until the counter catches up, and rule edits are not delivered to them meanwhile; the server counts this in `yuzu_server_guardian_agent_generation_ahead_total`. See "Restoring the policy generation" in [Guaranteed State](guaranteed-state.md).
- **A supported, audited way to raise the server's policy generation.** `POST /api/v1/guaranteed-state/policy-generation/raise` and the MCP tool `raise_guardian_policy_generation` set the generation to a target of `1` to `9007199254740991`, never lower it, and push nothing: the heartbeat reconcile converges the agents behind the new value. They are the supported recovery for the agents-ahead state above, and take the place of a manual database edit, which remains only as a last resort. The caller must be an administrator and must send `acknowledge_rule_set_replaced: true`, because the raise converges every agent behind it to the rule set the server holds at that moment. Check the rule store and the deployed Baselines first. When the server holds no rules or no deployed Baseline (the usual state after a rebuild or the move from SQLite) the call is refused unless it also sends `acknowledge_empty_rule_set: true`, meaning every agent behind the new value converges to zero guards. REST applies MFA step-up when the account is enrolled and its proof is stale (a SAML session is refused, an API-token session is exempt, `--mfa-step-up-window-secs 0` disables the gate, and with `--mfa-enforcement optional`, the default, an administrator who has not enrolled is not stepped up, and neither is an SSO (OIDC) administrator whose identity provider sent no MFA claim), requires a same-site `Origin` or `Referer` on a cookie-session call, and refuses service-scoped and MCP-tier bearer tokens; MCP has no MFA, and its protection is the supervised tier with an approval plus the administrator check. Each call is audited as `guaranteed_state.policy_generation.raise` and counted in `yuzu_server_guardian_policy_generation_raise_total`.
- **A read-only way to read the server's policy generation.** `GET /api/v1/guaranteed-state/policy-generation` and the MCP tool `get_guardian_policy_generation` return `generation` (the stored value) and `ceiling` (the largest target a raise accepts), so the value can be read before a raise target is chosen. They need `GuaranteedState:Read` and are refused for a service-scoped API token. A degraded read is a `503` or a retryable MCP error, never a generation of `0`. They change nothing; the REST call writes no audit row on success.

**New flags (all per replica).** `--guardian-reconcile-budget-ms-per-s` (default `500`), `--guardian-reconcile-burst-ms` (default `1000`) and `--guardian-reconcile-max-per-s` (default `1000`), each with a `YUZU_GUARDIAN_RECONCILE_*` environment variable; see [Server Administration](server-admin.md#sizing-the-guardian-reconcile-budget). The defaults are provisional starting values, not derived from fleet measurement. No flag needs setting to upgrade.

**Who notices.** In steady state (no policy change), only agents that are behind are re-pushed, so `shed` stays near zero. Admission matters after a policy bump or a fleet-wide restart, when many agents are behind at once. At an estimated 5 ms per admitted push (not measured end to end), one replica at the defaults admits about 100 pushes per second, so a fleet of 3,000 agents converges in about 30 seconds and a fleet of 30,000 in about 5 minutes; use the `yuzu_server_guardian_reconcile_duration_seconds` histogram to replace the estimate with your own figure.

**What you will see.**

- `yuzu_server_guardian_reconciles_total{result="shed"}` rising after a bump on a large fleet. This is the budget working, not a fault, and no alert ships for it.
- `result="degraded"` and `guaranteed_state.reconcile` audit rows beginning `heartbeat reconcile ABORTED` during a tag or property store outage. These rows are new for a scope-read failure. They do not raise `YuzuGuardianReadDegraded`; `YuzuGuardianReconcileDegraded` and the tag-store and custom-properties read-degrade alerts (`YuzuTagStoreReadDegraded`, `YuzuCustomPropertiesReadDegraded`, all warning severity) are the alerts that fire for it. `YuzuGuardianReconcileDegraded` also fires when `yuzu_server_guardian_reconcile_exceptions_total` keeps rising.
- `yuzu_server_guardian_reconcile_exceptions_total` rising: the reconcile hook threw out of the reconcile flow into the heartbeat handler. The exception is caught and logged as a warning and the rest of that heartbeat's ingestion still runs; the counter makes a persistent failure visible, and `YuzuGuardianReconcileDegraded` fires when it keeps rising.
- Agents with an armed rule keep it during such an outage; an agent that has nothing armed yet receives no rules, scope-free rules included, until the store recovers.
- A dashboard Baseline deploy or delete whose fan-out is abandoned because a store read degraded is audited `result=degraded` (detail containing `fan-out deferred to reconcile`) and shows a warning toast; the Baseline change itself is saved. The reconcile converges the fleet once the store recovers only if the generation bump succeeded.
- `yuzu_server_guardian_agent_generation_ahead_total` rising: at least one agent holds a policy generation above the server's. It does not count agents, is sampled at most once a minute per replica, and the shipped alert `YuzuGuardianAgentGenerationAhead` (warning) fires on it. Follow the restore runbook in [Guaranteed State](guaranteed-state.md), which uses the raise operation above.

**Rolling upgrades with more than one server.** A replica still on the previous release keeps the old behaviour (no budget, and a narrowed push on a degraded tag or property read) until it is upgraded. The REST, MCP and dashboard policy-bump fan-out now also aborts on a degraded tag or property read (#5610): REST answers `503`, MCP returns an internal error with a retry hint, and the dashboard answers `200` with a warning toast. A replica still on the previous release narrows the push instead.

No config or data migration is required. The agent binary does change (the lower-generation refusal above); agents that have not been upgraded keep the previous behaviour.

## Behaviour change: an over-long facet value is left out of the response's facets (#5623)

**What changed.** A facet value over 2048 bytes (measured in bytes on the value as stored) is now
excluded from a response's facets, never truncated. The response row, its output and every other facet
of that response still persist. Before, one such value made the whole facet insert fail and the response
lost ALL of its facets. The limit exists because the value is part of two database indexes, which refuse
an entry over about 2.7 KB. A new counter, `yuzu_server_response_facets_dropped_total{reason}` (`value_too_long`,
`cap`, `batch_failed`), counts the distinct (column, value) facets that did not persist; it is
published only after the response commits, is pre-seeded at 0 at boot, and a failed commit publishes
nothing. No alert rule ships or is owed: it is a data-completeness signal, and a per-response marker
and alert are tracked in #5630. See [`metrics.md`](metrics.md).

**Stored values.** Older servers indexed values that fit the database index limit: about 2.6 KB for an
incompressible value (less the instruction id length), and far more for a value that compresses well
(measured on PostgreSQL 18.4: 99,999 bytes of repeated text inserted, 499,998 were rejected). So values
from 2049 bytes up to that limit were indexed before and are not now. Rows already stored by an older
server stay readable until retention removes them.
Facet rows are removed with their response by the existing reaper (`--response-retention-days`,
default 90); nothing new is added.

**Effect on the dashboard.** For newly ingested responses a value over 2048 bytes is no longer indexed,
including values between 2049 bytes and about 2.6 KB that older servers could index, and compressible
values far larger than that. The facet filter, the dropdowns and the group-from-results and create-group
counts therefore show nothing or "0 agents" for such a value, and a direct group-from-results submit
answers `422` "No agents match" and creates no group when no agent matches. Every one of these surfaces
now says so when an active exact-value filter (typed, or applied by a saved View's default) is longer
than 2048 bytes:

- **Results page.** A static hint in the results summary, "A filter value is longer than 2048 bytes.
  Newly stored responses do not index values that long, so this filter may match nothing. Clear the
  filter (or switch the View to Default) and use the Search box." The hint never repeats the value, and
  the results, counts, Create Group button and the `422` are unchanged.
- **REST agent-count preview and MCP preview tool.** `GET /api/v1/management-groups/agent-count-preview`
  and `preview_management_group_agent_count` add `unindexed_filter_keys` to the result: the filter keys
  (for example `output`, never the values) whose value is longer than 2048 bytes, measured as ingest stores it (a NUL or invalid UTF-8 byte counts as 3). It is always present
  and is empty when no filter is over the bound. When it is not empty, `agent_count` can be 0 or an
  undercount. `agent_count`, the status codes and the `503` degrade are unchanged, so a client that
  ignores the new field behaves as before.
- **Create-group form.** In place of "N agents will be added" it shows a static sentence, "A filter value
  is longer than 2048 bytes. Newly stored responses do not index values that long, so the agent count
  may be wrong." The submit button works as before.
- **Direct group-from-results submit.** It still answers `422` and creates no group. When the `422` is
  for an empty selection while a filter value is over the bound, the message adds "A filter value is
  longer than 2048 bytes; values that long are not indexed in newly stored responses, so this may be an
  undercount."

For a value in the 2049 bytes to about 2.6 KB band the answer 0 can be wrong: agents whose newly
ingested output contains the value are not counted, because the value is not indexed. Rows ingested
before the upgrade, when older servers indexed it, are still counted, so the count from older rows can
still match.

**5,000-facet cap.** Above 5,000 distinct facets in one response, the facets kept are now chosen in a
fixed order: most lines first, then column index ascending, then value ascending. Before, they were
whichever the server happened to hold first, so a rare value could be cut and the choice was not
repeatable. Different rare values may therefore survive or be lost compared with before.

**Lost facets are not recoverable.** A response whose facets were lost (`batch_failed`, or cut by
`cap`) has no facets re-derived later, and nothing marks the response as affected (#5630).
**What to do depends on the reason.** `batch_failed` (the facet insert was refused, for example by an
unusually long echoed command id): run the command again; the new run gets a fresh response, and
RECREATE any static group built from the affected response from the NEW run, because running the
command again does not repair an existing group. `cap`: the same output keeps the same 5,000 facets,
so a re-run cuts the same ones; use a command or filter that returns fewer distinct values, or accept the
short result (#5630 tracks a marker). `value_too_long`: there is nothing to re-run, the value is never
indexed. To find a response that lost facets, search the server log (a `cap` or `batch_failed` response
logs a warning with its `response_id`); a `value_too_long` exclusion logs only at debug level, so at the
default level only the counter shows it.

**Rolling upgrade.** The change is server-only: there is no schema, configuration, agent or gateway step,
the order in which replicas are upgraded does not matter, and rolling back is starting the previous
server binary. What differs during a rollout:

- **Ingest decides the facets.** A facet is lost, or kept, on whichever replica ingested the response. An
  old replica that ingests a response carrying a value too long for the database index drops ALL facets
  of that response; a new replica excludes only the long value and keeps the rest.
- **Every replica reads the same table.** Every replica reads the same `response_facets` rows, so a group
  built from a response that an OLD replica ingested is short whichever replica builds the group.
  Upgrading the replica that serves the group does not repair it; use the workaround above.
- **A typed filter with a NUL or invalid UTF-8 byte.** A new replica matches such a filter in the form it
  is stored in; an old replica cuts a NUL filter short at the database (so it can match a different
  value) and fails the read for invalid UTF-8, which shows as an unavailable count. During a rollout the
  same request can therefore answer differently on different replicas.

See [`response-store.md`](response-store.md) (Facets are bounded).

## Behaviour change: the last administrator can no longer be deleted or demoted (#4966)

**What changed.** Deleting (deactivating) an account and demoting a local `admin` account now go through
one guarded write that refuses to remove the last member of a protected administrator population: the
active local `role='admin'` accounts (with RBAC enforcement on or off) and, with enforcement on, the
accounts that hold the `Administrator` grant. This covers the dashboard user delete and role change
(`409`) and every SCIM deactivation, delete, `active:false` and group-derived demotion (`409`,
`scimType` `mutability`). It is a recovery rule, not proof that anyone can sign in. The audit results
and the new counters are listed in the changelog entry and in `docs/user-manual/rbac.md`,
"Last-Administrator guard for account deactivation and demotion".

**What to do.**

- **Check before you upgrade or demote anyone.** `SELECT count(*) FROM auth.users WHERE role='admin' AND is_active;` should return at least 2, so no ordinary operation has to be refused.
- **Drain old replicas first.** A replica running an older build does not enforce the rule, so during a
  rolling upgrade drain the old replicas before relying on it. There is no schema change.
- **A rollback to an older binary silently drops the guard.** Nothing in the database remembers it: the
  older binary will delete or demote the last administrator without refusing.
- A server with an authentication database but no RBAC store does not start (a boot self-check), and at
  runtime the same condition fails closed. Fix the RBAC store before starting.
- SCIM connectors: expect `409` on a deprovision of the fleet's last administrator and `503` with
  `Retry-After: 2` when the guarded write times out. A refused deprovision leaves the person's account
  active until an operator acts, and raises a critical analytics event. SCIM provisioning now reads the
  RBAC store even when enforcement is off. **Behaviour change: `active:true` on a tombstone.** A SCIM
  `PATCH`/`PUT` with `active:true` on a deactivated resource whose role is not `user`, or whose username
  holds an `Administrator` grant, now answers `404` (audited `scim.user.provenance_denied`, counted on
  `yuzu_scim_provenance_denied_total`) instead of reactivating the account. SCIM can deactivate the holder
  of an `Administrator` grant but cannot reactivate it until the grant is removed (MCP
  `unassign_rbac_role`); an elevated tombstone has its role cleared with
  `UPDATE auth.users SET role = 'user' WHERE username = '<name>' AND NOT is_active;` (see `rbac.md`).
  A Group request whose role recompute is incomplete (a refused or failed demotion, a
  member whose read failed, or promotions skipped after a store failure) now records one
  `scim.group.recompute_incomplete` audit row, and its success row says `recompute=incomplete`. Known
  limits of the Group recompute are listed in the SCIM provisioning guide.

## Behaviour change: `POST /api/instructions/{id}/execute` now validates `params` against the stored schema

**What changed.** The route checks the request's `params` against the definition's stored
`parameter_schema` and answers `400` (`invalid params: <path>: <reason>`) when they do not conform. The
check runs after the permission checks and before the approval gate, so a refused call creates no
approval ticket, execution row or dispatch. It is strict: a name the schema does not declare, a value of
the wrong type or outside `enum`, `pattern`, `minimum`/`maximum` or length bounds, a missing required
parameter, a string containing a NUL, and a non-object `params` are all refused. A definition with no
stored schema (empty, whitespace or `{}`) is not validated. A stored schema that cannot be prepared makes
the route answer `500` instead of dispatching. A schema is also checked when it is written:
`POST /api/instructions/import` refuses an over-limit or invalid `parameter_schema` with a `400`, and a
bundled definition that fails the same check makes the server refuse to boot (the golden test guards the
shipped content). Updating a definition (`PUT`, the YAML editor, response templates) keeps its stored
schema. Details: [REST API](rest-api.md), [Instructions](instructions.md#parameter-validation).

**Who is affected.** Callers that send something the stored schema does not accept:

- **Names the definition does not declare.** They used to ride through to the plugin; they are now `400`
  (path `/*`, the name is not echoed). Six shipped definitions under-declared what their plugin reads and
  are corrected in this release: `agent.content_dist.cleanup` (`hours`), `agent.content_dist.execute_staged`
  (`expected_hash`), `device.wol.check` (`timeout_ms`), `device.agent_actions.set_log_level` (any letter
  case, plus `warning` and `err`, which the agent accepts), `workflow.config_search_and_replace`
  (declares `path`, `search`, `replacement`, `regex`, `case_sensitive`, `dry_run`, `max_replacements`
  and the retained `base_dir`) and `workflow.version_compliance_check` (declares `path`, `minimum_version`
  and `base_dir`). The two `workflow.*` definitions used to declare
  parameter names their plugin never read.
- **Values outside an enum or a bound.** `enum` is case-sensitive (`"True"` and `"1"` are refused for a
  `true`/`false` enum), and a value above a declared `maximum` (or below a `minimum`) is `400` where a plugin
  may have clamped it (for example `device.agent_logging.get_log` `lines` above 500).
- **`""` and `null` for optional parameters.** They are values, not omissions: they are refused for an optional
  integer, `enum` or `pattern` parameter. Omit the key instead.

**Not affected.** The 7 shipped definitions that have no `parameters:` block and so store no schema
(`windows.app_control.wdac_policy`, `windows.app_control.applocker_policy`,
`crossplatform.local_security_policy.password_policy`, `...lockout_policy`, `...audit_policy`,
`...sudoers` and `windows.rdp.status`), definitions saved from YAML or created in the dashboard, and every
other dispatch surface (workflow steps, schedules, policy remediation, result-set producers, MCP
`execute_instruction`, `POST /api/command`), which do not validate yet.

**A stored schema is not refreshed by an upgrade.** The bundled reseed inserts a definition only when its id
is absent (`ON CONFLICT (id) DO NOTHING`), so the six corrections above reach fresh installs only; an existing
install keeps the old stored schema and keeps refusing the same calls until it is replaced (export the
definition, delete it and import it again, signed unless the server allows unsigned definitions; see [Replacing a stored parameter schema](instructions.md#replacing-a-stored-parameter-schema)). Comparing the
parameter declarations at `v0.14.0` with this release, exactly 6 definitions differ in what the server
enforces (the six above), and 13 more differ only in `description` text and enforce what they did
(`agent.content_dist.upload_file`, `device.agent_logging.get_log`, `device.event_logs.errors`,
`device.event_logs.query`, `device.filesystem.find_by_hash`, `device.filesystem.read`,
`device.filesystem.search`, `device.filesystem.search_dir`, `device.script_exec.bash`,
`device.script_exec.exec`, `device.script_exec.powershell`, `device.windows_updates.patch_connectivity`,
`workflow.patch_connectivity_audit`).

**Detecting it.** Each refusal writes an `instruction.execute` audit row: `result=denied` with detail
`reason=param_schema path=<path>` for a `400`, or `result=failure` with `reason=param_schema_invalid` for the
`500`. Each also increments
`yuzu_server_instruction_param_rejected_total{route="instruction_execute",reason}`. See
[Audit log](audit-log.md) and [Metrics](metrics.md).

**Rollback.** No migration and no schema change. Rolling the server back removes the check, and while replicas
run different releases the same call can be refused by one and accepted by another. A release without the check
still rewrites a stored schema in one case: a YAML-editor save on the older release writes `{}` over it, because
that route builds the definition from the YAML alone. The other update routes of the older release (`PUT`,
response templates) write back the schema they loaded. A definition that was hit this way is not validated, on
this release or any other, until its schema is replaced (see
[Replacing a stored parameter schema](instructions.md#replacing-a-stored-parameter-schema)); rolling forward
does not restore it.

## Behaviour change: response routes parse numeric parameters strictly and exports are bounded (#4644, #4703)

**Breaking for scripts that relied on a malformed value being silently misread.** On the legacy
`/api/responses/{id}[/aggregate|/export]` routes, the `/api/v1/responses/{id}[/aggregate|/export]`
routes, `GET /api/v1/executions/{id}/responses` and MCP `query_responses`, `status`, `since`,
`until` and `limit` (and the legacy catch-all route's `offset`) must now be one whole base-10 integer.
A value that used to be read as a different one is now `400` (`-32602` on MCP): `since=1e9` (was
epoch second `1`), `status=0x1` (was `0`), `limit=100abc` (was `100`), `since=1.5` (was `1`),
a leading `+`, whitespace, and a `status` below `-1` (was "no filter"). An empty value and a value
too large for its type were already `400`.

**Who is affected, and what to do.**

- Scripts that build `since`/`until` from `date +%s.%N` or any fractional timestamp: send integer
  seconds (`date +%s`).
- **Breaking:** scripts and integrations that call the legacy `GET /api/responses/{id}`, `GET
  /api/responses/{id}/aggregate` or `GET /api/responses/{id}/export`: each now writes a
  `response.read` **success** audit row on every served read and is **fail-closed**, like its v1
  twin. When the audit store is down (or the row cannot be persisted) the route answers `503` with
  `Sec-Audit-Failed: true`, an A4 envelope (`retry_after_ms: 5000`) and no data, where it used to
  serve the read unaudited (all three routes, `get`, `aggregate` and `export`, used to answer `200` with the
  data even when the audit write failed). The scope-drop `denied` row on all three is fail-closed too, so a
  management-group-scoped caller whose drop row cannot be persisted gets the same `503`. Retry on
  `503`. A SIEM rule keyed on `response.read` now sees `result=success` rows with
  `detail=legacy response <query|aggregate|export> cid=<id>` from these routes as well as the v1
  ones; a global (unscoped) caller used to leave no row at all on `get` and `aggregate`.
  Every served read on these routes now adds one audit INSERT (the audit reaper's retention cap is the
  only backpressure), so a script that polls `/api/responses/*` raises audit volume in proportion to its
  request rate.
- Scripts that send `until=0` or a **negative** `since` or `until` to a response route: it is `400`
  now. A negative bound, and `until=0`, used to be read as "unbounded", so a window computed as
  `now - n` that went past the epoch silently returned the whole result. Omit the parameter for
  "no bound on that side". `since=0` stays valid and matches exactly what omitting `since`
  matches; no script that sends `since=0` changes behaviour.
- Scripts that send a **negative** `since` or `until`, or `until=0`, to other epoch-bounded reads
  (the execution-statistics, legacy audit, auth-sample and inventory-query routes): it is `400`
  now too, with the same fix (omit the parameter for no bound). The list is under
  [Behaviour change: numeric query parameters on other routes](#behaviour-change-numeric-query-parameters-on-other-routes-are-parsed-strictly-too-4644).
- MCP clients that send `"limit": null` or `"status": null`, or a float or string for either: omit
  the key to get the default. A `status` above `2147483647` and an unsigned value above
  `9223372036854775807` are `-32602` too (the latter used to wrap to `-1`, "any status"; the same
  fix applies to every other MCP argument read with the strict integer reader, 16 call sites).
- Callers that pass `limit=0` or a negative `limit` to the legacy export: it now serves one row
  (clamped to `1..10000`, like the v1 export), and its JSON `count` is the number of rows served.
  The legacy list route caps an explicit `limit` at 1000; zero or below still means its default of
  100. When the caller asked for more than 1000 and got a full 1000-row page, the legacy list
  body now carries `"result_truncated_by_cap": true` (absent otherwise).

**Exports are bounded.** Both export routes stop at 50 MiB of row payload (`output` plus
`error_detail`) in addition to the 10,000-row limit, and the cut is made inside the database query,
so a large export no longer loads every row into the server first. The cap is not operator-tunable.
A cut export (row limit with more rows left, or the byte cap) is marked with a top-level
`result_truncated_by_cap: true` (legacy JSON) or `pagination.result_truncated_by_cap` (v1 JSON),
and a cut CSV ends with one extra trailer record, `# result_truncated_by_cap cause=row_cap` (or
`byte_cap`), padded to the header's width (7 fields legacy, 10 on v1). **A CSV parser that expects a
number in the `id` column will fail on that record, and only on a cut file; that is deliberate, so a
cut file is never read as complete.** An uncut CSV is byte-identical to before. A cut export also
carries an `X-Result-Truncated-By-Cap: true` header (CSV) and a download name
`responses-<id>-truncated.json` or `.csv`; a plain `curl -o out.csv ...` keeps neither, `curl -sS -D
- -o out.csv ...` shows the header and `curl -OJ` keeps the name. The 50 MiB cap counts payload
bytes, the last row kept can run past it by up to its own size (about 4 MiB for text output, up to
about 12 MiB for output dense in invalid bytes or NULs; a terminal frame's `error_detail` is cut the same way), and a result under 50 MiB of raw payload can
still be cut when its escaped serialized form crosses the cap. A legacy export of an id containing a
character outside `[A-Za-z0-9._-]` is now downloaded under a name with that character written as `_`.
A quoted CSV cell can contain text that looks like the trailer, so read the file as CSV and take the
final record rather than matching lines. There is no
cursor: to read past a cap pull once per `agent_id`, or set `until` to the oldest `timestamp`
received (inclusive, so de-duplicate on `id`).

**Rolling upgrade.** Replicas on the old and the new build answer a malformed value differently
(`200` versus `400`), so a client can see both during the rollout. No configuration or data
migration is needed. Two new counters report the effect:
`yuzu_server_response_param_rejected_total{surface}` and
`yuzu_server_response_export_truncated_total{surface,cause}`
([Metrics](metrics.md#response-store-metrics)).

## Behaviour change: numeric query parameters on other routes are parsed strictly too (#4644)

**Breaking for scripts that relied on a malformed value being silently misread.** The strict
parsing the response routes got (above) now also covers the routes listed in the REST API
reference under [Numeric Query Parameters](rest-api.md#numeric-query-parameters-4644): the
execution-statistics routes, the executions lists, the audit routes, the instruction, product-pack,
workflow and compliance lists, the patch lists, the software-inventory list, the fleet-topology
`machines_max` and the app-performance compare `window`. A value that is not one whole base-10
integer now returns `400` where it used to be read as something else: `limit=100abc` (was `100`),
`since=junk` on the statistics routes (was `0`, "from the beginning"), `?limit=abc` on
`/api/analytics/recent` and the patch lists (was ignored), `window=7days` (was `7`).

On MCP, `query_audit_log` answers `-32602` for a `since`, `until` or `limit` that is not a JSON
integer or does not fit a signed 64-bit value (a string used to mean `0`, unbounded, and
`18446744073709551615` wrapped to `-1`), and the app-performance compare tool does the same for
`window`. Other integer arguments that do not fit saturate instead of wrapping, except three tools
where a saturated value would be harmful and the argument is strict and bounded instead (`-32602`
otherwise): `create_offload_target` `batch_size` must be 1 to 10000 (the declared schema range, now
enforced), `mint_upload_grant` `declared_max_size` must be a JSON integer that fits a signed 64-bit
value, and `create_guardian_rule` `version` must be 1 to 2147483647. `mint_engine_credential`
`ttl_days` of the wrong JSON type is `-32602` too (nothing is minted; it used to fall back to the
90-day maximum). Security-gating MCP arguments are strict too: `issue_code_signing_cert` `validity_days` must be a
JSON integer from 1 to 730 (`4294967297` wrapped to a 1-day certificate; a string, float or `null` took the
365-day default), `mint_upload_grant` `ttl_secs` must be a JSON integer of at least 1 (a wrong type, `0` or a
negative value minted the 900 s maximum; larger values still clamp), `create_api_token` `expires_at` must be `0`
or a future epoch (a negative value minted a token that never expires), and `activate_platform_license`
`seat_count` and `expires_at` must be integers of at least 0 (a negative `expires_at` was perpetual); each is
`-32602` and creates nothing. A wrong-typed boolean on `create_guardian_rule`/`update_guardian_rule` `enabled`,
`push_guardian_rules` `full_sync` and the engine-principal `include_revoked` is `-32602` instead of a bare
HTTP 500, and `create_offload_target` now neutralises the name it writes to audit rows. The two bounds now hold
at the REST twins and in the stores, so no writer bypasses them: `POST /api/v1/offload-targets`
reads `batch_size` as a 64-bit value and answers `400` outside 1 to 10000 (an oversized number is
rejected, not wrapped) and for a float, string, boolean or `null` (a float such as `5.5` used to be
truncated), `POST /api/v1/guaranteed-state/rules` answers `400`
for a `version` outside 1 to 2147483647, and `PUT /api/v1/guaranteed-state/rules/{id}` and MCP
`update_guardian_rule` refuse a rule whose stored version is already at 2147483647 or above (`409` on REST,
`-32602` on MCP) instead of overflowing the version bump. The store enforces the range only when a
write changes the version, so a rule that already holds an out-of-range stored version can still be
enabled or disabled from the dashboard. The MCP tools `get_execution_statistics_by_agent` and
`get_execution_statistics_by_definition` answer `-32602` for a `limit` below 1 (the schema minimum;
it used to be replaced by the default 50), and so do their REST twins, `GET /api/v1/execution-statistics/agents` and `/definitions` (`400` for a `limit` below 1 or malformed). Two more REST inputs are new `400`s: the `limit` in the body of `POST /api/v1/inventory/query` and `POST /api/inventory/query` (below 1 or not an integer; above 1000 still clamps to 1000, and 4294967297 no longer wraps to 1), and the `ttl_days` of `POST /api/v1/engine-principals/{id}/credentials` (present but not a JSON integer from 1 to 90; absent still means 90). That mint route's body is optional only when it is empty or whitespace-only: a truncated document or a body that is not a JSON object (`[]`, `5`, `"x"`, `null`) is now `400` and mints nothing, where it used to mint the default 90-day credential. `{}` and an object without `ttl_days` still mint 90 days.

A negative `since` is refused (`400`, `-32602` on MCP) on the legacy `GET /api/audit` and MCP
`query_audit_log`, and so is an `until` of `0` or below (a negative `since` or `until`, and an `until`
of `0`, each used to mean no bound and are new `400`s here). The same holds for a negative `since` on
`GET /api/v1/execution-statistics/definitions`/`agents` and their MCP twins, for `to=0` on
`GET /api/v1/audit/auth-sample`, and for an `until` of `0` or below (or a non-integer bound) in the
body of `POST /api/v1/inventory/query` and `POST /api/inventory/query`; a non-integer `since` or
`until` in an inventory query body made the body read throw and is a clean `400` now. The bounds are
presence-tracked now: `-3600` and `until=0` used to mean no bound and returned the whole log,
statistics set or inventory. Omit the parameter for no bound; `since=0` (`from=0` on the auth sample)
is accepted and matches the same rows as omitting it. On the auth-sample export a present but empty
`from` or `to` is accepted as unbounded on that side. `GET /api/v1/audit` follows the same rule: an
earlier build of this release line read `0` as unbounded there; an `until` of `0` or below (or a
negative `since`) is now `400`.

The same strictness now covers the dashboard fragments' `page`/`per_page`, the software
inventory (the three software fragments answer `200` with an `inv-caveat` note for a malformed
`limit` and ignore a well-formed one, which uses a fixed page size), DEX perf, network quality, hardware and CA-issued lists, the notification, webhook and
offload delivery lists, the DEX, network and result-set `limit` and the Guaranteed State events `limit`/`offset` (trailing characters are `400`; an integer outside the result-set page range still uses the default page size),
the pre-flight run list `limit`, the pre-flight run form's `min_gib` and `window` (a malformed value
or a negative `min_gib` is `400`; an empty field keeps its default; a `window` of zero or below uses 30
minutes and a larger value is clamped to 1 to 2880 as a 64-bit value, so one beyond a signed 64-bit
integer is `400`; see [Pre-flight](preflight.md)), the hardware sync poll's `await_since`
(a malformed freshness bound used to read as "no bound"), the TAR process-tree `node` and the
`GET /api/v1/events` `?since` cursor (the workflow stream has the header only). A malformed
`Last-Event-ID` header is served live only (nothing replayed, never the whole buffer) rather than
a `400`, and `-1` and `5abc` are never accepted as cursors (`5abc` used to replay from 5). On the
query-parameter routes, a parameter that is present but empty (`?limit=`) is malformed, not
absent, `GET /api/v1/audit` `limit` included, except `limit` on the software list and catalogue
routes and fragments, where an empty `limit=` means the default (see
[the software installs read](#behaviour-change-the-software-installs-read-validates-its-inputs-and-audits-an-out-of-scope-target)).
The verify fragment's `window`
is refused with its usual `200` note instead of a `4xx` (the dashboard drops `4xx` bodies).

Four admin forms stop silently saving a different value than the one typed. A malformed
`min_devices`, `window_seconds` or `cooldown_seconds` on the DEX blast-radius thresholds is a `400`
and saves nothing (it used to persist the clamped minimum). On the enrollment-token forms and the
API-token `ttl_hours`, `0x5` used to read as `0`; `max_uses` `0` means unlimited and a TTL of `0`
means no expiry, so a mistyped limit minted an unlimited or never-expiring credential. Only an
empty field, or a value that parses to a literal `0` (`0`, `-0`, `00`), means unlimited or no
expiry now, and a negative `ttl_hours` is refused (it would have computed `0`). The API-token form
refuses with its usual `200` feedback span and mints nothing; the other forms answer `400` plus an
error toast. On the batch route an empty `max_uses` defaults to `1`. A malformed `rollout_pct` on an OTA
package upload or rollout change is a `400` instead of silently becoming `100`. **Behaviour change on
the rollout change route only:** an empty `rollout_pct` and a value above `100` are now `400` as well
(an empty value used to mean `100` and a larger one was clamped to `100`); a negative value still
clamps to `0`; the upload route keeps an empty value as `100`, clamps a larger one to `100` and a negative one to `0`, and refuses only a malformed value. A negative `limit` or `offset` on `GET /api/notifications`, and a negative `limit` on the patch lists
(`GET /api/patches`, `GET /api/patches/deployments`), is `400` too (the store answered an empty `200`),
and so is a negative `limit` on the legacy `GET /api/policy-fragments` and `GET /api/policies` (it
reached Postgres as `LIMIT -1` and answered `503`; the `/api/v1/` policy routes clamp it as before).
A malformed or out-of-range enrollment-token number now also writes an `enrollment.token_create` or
`enrollment.bulk_token_create` row with `result=denied` and `detail=invalid_numeric_parameter` (see
[Audit Log](audit-log.md)).

Security-gating numbers in JSON request bodies are strict too. **Before / after:** `POST /api/v1/tokens` `expires_at` of `-1`, or a value above 9223372036854775807 that wrapped to `-1`, minted a token that never expires, `5.5` or `1e3` minted an already-expired one, and a string, boolean or `null` (or a non-object body) was a bare `500`; now each is `400` and mints nothing (`0` or omitted still means never expires, and a past epoch is refused). `overlap_secs` on `POST /api/v1/tokens/{id}/rotate` and `POST /api/v1/engine-principals/{id}/credentials/rotate` must be a JSON integer, and a non-blank body that is truncated or not an object is `400` instead of rotating with the 7-day default (an empty body still takes the default). `version` on `POST /api/v1/guaranteed-state/rules` must be a JSON integer in range (`5.5` was stored as `5`). `ttl_secs` on `POST /api/v1/upload-grants` must be a JSON integer of at least 1 when present (a wrong type, `0` or a negative value used to mint the 900 s maximum). On `POST /api/settings/enrollment-tokens/batch` a JSON number for `count`, `max_uses` or `ttl_hours` used to be silently ignored, so the documented curl example minted single-use tokens that never expired; numbers and numeric strings are now both honoured, a float, boolean, `null`, overflow or malformed body is `400`, and an empty string still means the default. An `ip_subnet` auto-approve rule with a malformed prefix is refused when added (`400`); a malformed one already stored used to throw out of agent registration and now never matches, so it never auto-approves. `POST /api/schedules` `interval_minutes` (1 to 35791394), `day_of_week` (0 to 6) and `day_of_month` (1 to 28) must be JSON integers in range (`4294967297` minutes became an every-minute schedule); `POST /api/schedules/{id}/enable` `enabled` must be a JSON boolean, the integer `0` or `1`, or the exact string `"true"` or `"false"` (an omitted key or a blank, empty or whitespace-only, body still enables), and any other string, another number, `null` or a malformed body is `400` and changes nothing (`{"enabled":0}` used to arm the schedule). `POST /api/command` `stagger` and `delay` must be integers from 0 to 300 (a float, string or `null` read as 0, so a delayed command ran immediately; a value above 300 was silently capped by the agent at 300 seconds and is now a 400). A result-set matcher `{"kind":"tar_rows_ge","n":N}` needs an integer N from 1 to 2147483647 on `POST /api/v1/result-sets/from-instruction-result` and the MCP `create_result_set_from_instruction_result` (`400` / `-32602`), and a `matcher` that is present but not a JSON object, or a `kind` that is not a string, is refused too (it used to be dropped, so every responder qualified; omit `matcher` for that default); a malformed `n` or `kind` already stored, or an `n` below 1, now matches no device instead of throwing in the maintenance tick or admitting everyone. The pre-flight form's `app_min`, `app_max` and `os_min` must be empty or a dotted-decimal version with an optional `-beta` / `+build` suffix; `abc`, `v4.2.0` or `4.2.x` is `400` and starts no run (it read as version 0 and passed every device). `POST /api/v1/license` `seat_count` and `expires_at` follow the MCP twin: JSON integers of at least 0, else `400` (the licence surface is dormant until the `LicenseStore` is wired, ADR-0048). Rolling upgrade: replicas on the old and new build answer these inputs differently.

Three more inputs that used to be read as something else are refused (`400` on REST, `-32602` on MCP), and one stored value is repaired:
a `conditions[].value` on the inventory evaluate and result-set routes that is a JSON number is
accepted with `==`, `!=`, `>`, `>=`, `<`, `<=` (and a boolean with `==` or `!=`); all six compare it
as a number against the raw stored value (exact for integers and for integer against a decimal, a stored
numeric string counting as that number; JSON integers are exact and every JSON float (a number written with a decimal point or exponent, such as `5.0`, `1e3` or `5.5`, or an integer outside `-9223372036854775808` to `18446744073709551615`, which arrives as a float) is refused because its original text is lost once parsed: send the decimal as a JSON string under `>`, `>=`, `<` or `<=`, which is accepted as a whole number within int64/uint64 (digits or an integer-valued exponent form such as `"1e16"`, read exactly) or with at most 15 significant digits, a magnitude below 2^53, a value that is zero or at least the smallest normal double, and a value within the range of a double, and a plain-decimal string such as `"1e400"` is refused instead of ordering lexically; `==` and `!=` with a string stay a text compare, so numeric equality covers JSON integers only; write a whole number as an integer up to `18446744073709551615` or as digits, and a string such as `"9007199254740993.0"` is read as that exact integer; a non-integer at or above 2^53 such as `"9007199254740992.5"` is refused), so **behaviour change:** a stored value that is not a number,
such as `"5 GB"` or `"N/A"`, no longer satisfies `>`, `>=`, `<` or `<=` against a numeric operand (it was read as `5`
or compared as text), and any other operand type is refused (a number used to become the empty string, so `{"op":">","value":5}`
selected every device that had the field); a string operand that is a plain decimal number (`"4"`, `"2e-7"`) is ordered numerically under `>`, `>=`, `<`, `<=`: a stored number or fully numeric string compares exactly (a stored integer within int64/uint64, including an integer-valued exponent spelling that fits (such as `"564141138995e7"`), and a stored decimal with a fraction of at most 15 significant digits and a magnitude below 2^53 compare exactly; any other stored decimal, one of more digits or a non-integer at or above 2^53, or a stored negative integer below `-9223372036854775808`, is compared as the nearest double), a stored string that merely starts with a number (a dotted version `"1.2.3"`, `"5 GB"`) has its leading number read and compared the same way (use `version_gte` / `version_lte` for dotted versions), and any other stored value (`"N/A"`, `""`, a boolean) never matches, where a JSON number operand never matches a stored string that is not a number in full; while `==` / `!=` and a non-numeric string operand such as `"v2"` are unchanged; a result-set matcher whose `column`, `op` or `value` is
present with the wrong type no longer qualifies every responder; the DEX `window` on
`GET /api/v1/dex/signals`, `/dex/scope`, `/dex/signals/{obs_type}` and their MCP tools (and `get_dex_device_score`) must be
`24h`, `7d`, `30d` or `all` (`90d`, a non-string such as `30` or `null`, or an empty `?window=` was answered with 7 days; only an omitted `window` keeps `7d`). Separately, a stored schedule `interval_minutes`
above 35791394 now advances instead of failing in Postgres on every tick (new schedules are capped at
that value).

Still lenient, and not an exhaustive list: the `n` retry-attempt counter on the live-snapshot poll
fragments (the deployment, device, hardware, DEX, pre-flight and TAR process-tree polls), which is
clamped to a fixed range per poll (1 to 100000 on the deployment and pre-flight polls, at most 50 on
the others), and values parsed from stored rows, agent output or server configuration rather than
from a request. Numeric path segments matched by a `(\d+)`
pattern (notification read/dismiss and the webhook routes) now answer `404` for an id that does
not fit a signed 64-bit integer; they used to fail with `500`. The auto-approve rule index answers
`200` with an audited `denied` row (`rule_not_found`) and changes nothing.

**What to do.** Send whole integers, and omit a parameter to get its default. No configuration or
data migration is needed, but review Settings > Auto-Approve for `ip_subnet` rules with a sign or an odd prefix (they match nothing, so those agents go to the pending queue), and optionally list API tokens with `expires_at=0` and enrollment tokens minted before the upgrade. During a rolling upgrade, replicas on the old and new build answer a
malformed value differently (`200` versus `400`).

## Changed: a degraded execution-statistics read is a 503, not an empty 200 (#4644)

`GET /api/v1/execution-statistics`, `/agents`, `/definitions`, `GET /api/v1/statistics` and the
four MCP statistics tools used to answer a store failure (execution store not open, pool timeout,
failed query) with `200` and an empty list or an all-zero summary, which reads as "no
executions". They now answer `503` with `retry_after_ms: 2000` on REST and a retryable error with
`retry_after_ms` on MCP. A filter or confined scope that genuinely matches nothing is still `200`
with an empty `data` array. Each degraded read also logs a warning on the server
(`ExecutionTracker::try_get_<reader> degraded: tracker not open`, `pool exhausted` or `query failed`).

**What to do.** Treat a `503` from these routes as retryable. A dashboard or script that read
`data: []` as "nothing to report" during an outage will now see the error instead.

## Changed: a saturated pre-flight response window is inconclusive (#4644)

Each pre-flight check reads its newest 50,000 responses for a run. On a very large cohort a
device that had answered could be pushed out of that window and then read as "no response" while
the runner kept re-dispatching. A device absent from a full window now shows **"inconclusive:
response cap reached"**, stays Incomplete (never in Deploy's go cohort) and the runner stops
re-dispatching that run; the run still completes at its deadline. Re-run against a smaller group
to resolve those devices.

## Behaviour change: per-agent execution statistics are confined to the caller's scope (#3526)

`GET /api/v1/execution-statistics/agents` and the MCP tool `get_execution_statistics_by_agent` used
to gate on a bare `Execution:Read` check. That check admits only a holder of a global grant, and it
returned one row per agent across every execution of every operator with no per-agent filter. A
management-group-scoped-only operator (no global grant) was refused with `403`. Both now go through
the same admit-then-filter fleet-read gate as `GET /api/v1/executions` (ADR-0017): the visible-agent
set is applied in the query before the grouping and the row limit, and an empty visible set returns
no rows, never the fleet. This widens who is admitted and narrows what a confined caller sees:
nothing a caller could read before is now refused, with one exception: the gate fails closed, so
when the RBAC or management-group store is not open the route answers a retryable `503`
(`retry_after_ms` 5000), even to a global admin, where the bare check answered `200`.

- **A group-scoped-only operator** goes from `403` to a `200` that carries only the rows of the
  agents it can see. A holder of a global grant sees the same rows as before.
- **A service-scoped API token on the REST route** used to be refused (`403`) by the bare gate. With
  RBAC enforcement on it is now admitted as a confined view: the token must clear the
  `ITServiceOwner` authority ceiling (the seeded role holds `Execution:Read`), and the rows are then
  intersected with the agents tagged for its service. A degraded tag store answers `503`. The MCP
  tool still denies service-scoped tokens, and widening that is a separate decision, not made here.
- **Confinement is effective only with RBAC enforcement on.** With RBAC off (the shipped default)
  the rollup is unfiltered for every authenticated caller other than a service-scoped token or an
  engine principal (a service-scoped token is refused `403` with RBAC off). Treat the confined view
  as available once you enable RBAC enforcement, not before.
- `GET /api/v1/execution-statistics/definitions` and the fleet summary carry no agent identity and
  keep the plain `Execution:Read` gate (the summary's `active_agents` is a fleet-wide count).
  `GET /fragments/executions` is not changed by this entry.
- A negative `since` on `/agents` and `/definitions` is `400` (see the previous section).

During a rolling upgrade, replicas on the old and the new build admit and return different row sets to
a confined caller.

## Behaviour change: the software installs read validates its inputs and audits an out-of-scope target

**Breaking for scripts that relied on a malformed value being tolerated.** `GET /api/v1/inventory/software` and MCP `query_installed_software` now share one parser with the catalogue routes:

- A `name`, `agent_id`, `version`, `kind`, `ecosystem`, `source` or `cursor` holding a NUL byte or invalid UTF-8, or one over its bound (`name`/`version` 1024 bytes, the others 256, `cursor` 2048), is `400` (`-32602` on MCP). A NUL byte used to reach the store and come back as a retryable `503`.
- `limit` must be one whole integer: `limit=12abc` is `400` (it was read as `12`), and an empty `limit=` now means the default (it was `400`).
- **MCP only:** a wrongly typed argument is refused with `-32602` instead of being ignored or converted. `version: 2.0` used to be dropped and read the whole fleet unfiltered, `agent_id: 123` was read as `"123"`, and an unsigned `limit` above `9223372036854775807` wrapped. `agent_id`, `name`, `version` and `cursor` must be strings and `limit` an integer that fits an int64; an in-range `limit` (for example `50000`) still clamps as before, and unknown argument names are still ignored.

**Audit trail addition.** A `denied` audit row (`inventory.software.query`, or `inventory.software.export` for an export; `mcp.query_installed_software` on MCP) is now also written when a request names an `agent_id` outside the caller's scope. The response is unchanged (under push-down: an empty page, `devices_omitted` `0`). A SIEM rule that counted `denied` rows from these routes will see them for this case too.

**Who is affected, and what to do.** Scripts that sent a malformed or over-long value, or a non-string MCP argument: send well-formed values. Scripts that retried a `503` on a NUL byte: it is a `400` now and will not succeed on retry.

## Behaviour change: a cut visualization, results fragment or TAR scan is reported (#4644)

The execution visualization route (`GET /api/v1/executions/{id}/visualization`), the dashboard
results fragment's unfiltered read and the TAR retention-paused scan page now read through the same
SQL-side 50 MiB payload cap as the response exports, and say so when it cuts.

- The visualization payload gains `result_truncated_by_cap: true` and `truncation_cause` (`row_cap`
  or `byte_cap`) on a cut read; `rows_capped` is now exact (it also fired on a read of exactly
  10,000 rows) and is the row cap only. The dashboard chart card shows a "Partial result" notice.
- The results fragment shows a "truncated" notice in its result summary.
- The TAR scan page shows a "Partial result" banner and qualifies its header counts; with no rows in
  the part that was read, its empty state says it cannot tell, instead of "still in progress" or "all
  clear". `GET /api/v1/tar/retention-paused` and `list_tar_retention_paused` gain a
  `result_truncated_by_cap` boolean (always present) and **also set `store_degraded: true` on a cut
  scan**, so a client that treats `store_degraded` as "the read failed" now sees it for a cut as
  well: test `result_truncated_by_cap` first to tell the two apart.
- None of these cuts is counted on a metric (see [Response export bounds](server-admin.md#response-export-bounds)),
  and the dashboard fragment and the scan page apply management-group scope after the fetch, so a
  confined caller can see the notice when every dropped row was outside their scope.
- The filtered results-fragment branch, the plain list routes and the internal reads are not bounded
  by this change.
## Gateway upgrade note: stream-status notifications and startup checks (#4632)

Read this before restarting a gateway that includes #4632 (the version table above has the headline). A gateway restart is required and disconnects every agent the node holds; there is no hot code load. What changes for an operator:

- **Breaking: a gateway whose configured `cluster_id` cannot be represented as UTF-8 now refuses to start.** The previous gateway started, then failed every notification. The name comes from `YUZU_GW_CLUSTER_ID` (which replaces the `sys.config` setting when set); a name with a surrogate, a code point above 16#10FFFF or bytes that are not UTF-8 stops the boot with a critical log line that names the source and never prints the value. A UTF-8 name in the variable on the shipped images (latin1 nodes) is not refused. In `sys.config` write a non-ASCII name as a string (`"Z\x{FC}rich"`) or as `<<"Z\x{FC}rich"/utf8>>`: a plain `<<"...">>` binary holding code points above 255 is truncated to bytes by the Erlang term reader and is accepted only if those bytes happen to be valid UTF-8, so always use the `/utf8` form. Check the configured name before you restart; the rules and the runbook row are in the `cluster_id` paragraph of [gateway.md](gateway.md#configuration).
- Out-of-range or invalid values of the circuit breaker settings now log a WARN that names the key and take the default (before, `0` for a reset timeout made the half open probe a hot loop, and `0` for the failure threshold opened the breaker on the first failure). The accepted ranges are 1 to 1000 for `circuit_breaker_failure_threshold` and 100 to 3600000 ms for both reset timeouts, and a reset timeout above the maximum now raises the maximum to match it with a WARN; see "Circuit breaker tuning" in [gateway.md](gateway.md#configuration).
- A failure inside the gateway's own request encoder no longer opens the circuit breaker, where the previous gateway counted it as an upstream failure. A held notification that cannot be encoded no longer blocks the queue: as the half open probe it is evicted with a WARN, and with the breaker closed an ordinary worker loses it and logs `Failed to notify stream status`.
- A `Register` with an agent id outside 1 to 256 bytes is now refused at the gateway edge with `INVALID_ARGUMENT`, without an upstream call. The server applied the same bound, so a conforming agent is not affected. Server statuses that mean the request itself was wrong (`INVALID_ARGUMENT`, `NOT_FOUND`, `ALREADY_EXISTS`, `FAILED_PRECONDITION`, `OUT_OF_RANGE`) no longer count as breaker failures, and a request over 4194304 bytes is refused in the gateway instead of being sent. The warnings a refused registration can trigger are limited to one line per second per kind, so during an outage `Upstream Register failed: circuit_open` is no longer one line per refused `Register`. During an outage read the `Circuit breaker:` lines and the ` (N similar line(s) suppressed since the last)` suffix: a `circuit_open` rejection never reaches the call, so `yuzu_gw_upstream_rpc_errors_total` does not count it. That counter now has a `code="encode"` series for a local encoder failure (alert `YuzuGatewayUpstreamEncodeErrors`), and the edge refusals are counted in `yuzu_gw_register_refused_total` (also visible as the suffix on the `Register refused` line). A refused `Register` no longer reaches the server, so the server's `yuzu_register_invalid_agent_id_total{source="gateway_proxy"}` does not move for it; use `yuzu_gw_register_refused_total{reason="agent_id_length"}` to see these. The alert `YuzuGatewayUpstreamEncodeErrors` fires at about ten `code="encode"` increases in 10 minutes (`increase()` is extrapolated), so one rejected request does not trip it.
- The sanitised peer address is sent to the server in the notification's informational `peer_addr` and is not sent in the registration request.

## Operator note: the software-inventory store migration (v7) is a hard cutover (#5172)

Schema v7 of the software-inventory store adds `package_id` and `source` columns and a row id to
`installed_software`. The row id is added with a table rewrite under an exclusive lock, so the first
start after upgrade takes time that grows with the table (about 10-20 s at 4M rows). A rolling upgrade is
not supported for this migration at this stage: above about 2 million rows stop every server replica,
then start one and let it finish; below that, start one replica first. The procedure, the row-count query
and the free-space guidance are in [Installed-Software Inventory](inventory.md) (Upgrading).

## Behaviour change: `yuzu-server.cfg` no longer overrides a stored password (#5274); passwords are now changed in the product (#5342)

**What changed.** Login now reads a local account's password from the PostgreSQL auth store (`auth.users`) **only**. Before this release the server loaded the password hashes in `yuzu-server.cfg` into memory at boot and checked them **first**, so a hash in the config file silently took precedence over the stored one on the server that loaded it. That is gone: the config file is now a **seed** — it provisions the first administrator into an empty `auth` schema, and is never consulted for an account the auth store already holds.

**Who is affected — the password reverts.** Anyone who reset a password by editing (or regenerating) `yuzu-server.cfg` and restarting — including re-running the Windows server installer with a new `/ADMIN_PASS` on an existing install. **That no longer changes the password, and a password rotated that way reverts on upgrade:** the password that works is the one in the auth store, which for most installs is the one the account was first created with, and the rotated one stops working. If you had "reset" the admin password through the config file, sign in with the **original** password (or recover as below). **If you rotated it because the old one was exposed, reset it in the product immediately after upgrading** — until you do, the exposed password is the live one. At boot the server logs a warning naming each config-file account whose hash differs from the stored one ("#5274 cfg is seed-only; stored credential wins") and sets the gauge `yuzu_auth_cfg_credentials_stale` to their count, so you can see which accounts this affects.

**The config file is still a bootstrap credential.** It seeds the first administrator whenever the auth schema is empty, so rebuilding onto an empty database (a lost or recreated Postgres, a restore onto a fresh database) brings back whatever password the file holds. Keep it protected, and change the administrator password in the product after any such rebuild. The reverse also holds: a **fresh install pointed at an already-populated database** (for example a reinstall, or a new server joining an existing cluster) seeds nothing — the installer's `/ADMIN_PASS` (or the first-run prompt) is written to the new config file but **ignored** by the server, and the accounts already in the database keep their passwords.

**Windows server installer.** On an upgrade (a `yuzu-server.cfg` already exists in `%ProgramData%\Yuzu Server`), the installer now **refuses** a non-empty `/ADMIN_PASS=` or `/OPERATOR_PASS=` with **exit code 11** before it stops the service or changes anything, instead of writing a config file the server would ignore. The interactive wizard skips its account pages on an upgrade. Remove those parameters from your upgrade command lines (SCCM/Intune packages included); see the Windows server installer section of [Server Administration](server-admin.md) (#5196 note).

**Breaking — the second first-run account and the Windows installer's `/OPERATOR_USER`/`/OPERATOR_PASS` are removed (#5343).** They were written to `yuzu-server.cfg` only and were never provisioned into the PostgreSQL auth store, so the account they created could never sign in. First-run setup now prompts for the administrator only, and a fresh Windows install that passes a non-empty `/OPERATOR_USER=` or `/OPERATOR_PASS=` is refused with **exit code 7** (nothing changed; an upgrade given `/OPERATOR_PASS=` still gets exit code 11, and an upgrade given `/OPERATOR_USER=` alone gets exit code 7). Remove both parameters from fresh-install command lines and create further accounts in Settings → User Management (`POST /api/settings/users`). Upgrades are unaffected: an existing installation keeps its accounts, and a leftover `yuzu-server.cfg` entry that has no stored account is reported by name in a warning at boot — delete that line.

**Rolling upgrades with more than one server.** A server still on the previous release keeps checking `yuzu-server.cfg` first and caching hashes, so it can keep accepting an old password after a change or reset made on an upgraded server, and it has no password routes (`404`). Upgrade every server before using **Change password** / **Reset password**, or before relying on a password change to lock someone out.

**Passwords over 1024 bytes stop working.** The new maximum applies at sign-in too: `/login` answers a password longer than 1024 bytes as a wrong password, without hashing it, and the attempt counts toward [account lockout](server-admin.md#server-cli-flags). An account whose existing password is longer than that (only possible if it was set outside the product, for example a hand-generated config entry) can no longer sign in. An administrator resets it to a shorter one (Settings → User Management → **Reset password**, then **Unlock** if it locked); if it is the only administrator, use the direct-SQL fallback in the [auth-db-recovery runbook](../ops-runbooks/auth-db-recovery.md#password-reset).

**What to use instead.**

- Settings → User Management → **Change password** on your own row (`POST /api/v1/users/me/password`), or **Reset password** on another local account's row (`POST /api/v1/users/{name}/password` — a **durable Administrator** only: with RBAC off your own account must hold the `admin` role, with RBAC on you need a user `Administrator` grant; a JIT elevation, an IdP-group admin role or a custom role is refused; plus MFA step-up). See [Authentication](authentication.md#changing-and-resetting-a-local-password) and [REST API](rest-api.md#post-apiv1usersmepassword). Non-admin users have no dashboard page for their own change yet and use the REST call (#5353).
- If no administrator can sign in at all: [auth-db-recovery runbook → Password reset](../ops-runbooks/auth-db-recovery.md#password-reset) (a direct-SQL fallback).

**Also in this release.** Passwords must be 12–1024 bytes (UTF-8 bytes, not characters). A change or reset is **one database transaction**: the new password, the sign-out of every session of the account on every server, the discarding of an unfinished MFA enrolment, the target's lockout (reset only) and the audit row are saved together or not at all — a refusal or failure (`503 audit_unavailable` / `store_unavailable`) changes nothing. After changing your own password you are signed out and sign in again — no replacement session is issued. A reset leaves the target's API tokens and any enrolled second factor in place (the response reports the token count). The configured break-glass account cannot be reset over the API. Neither action has an MCP tool, by design (#5357 tracks a temporary-password tool). `/login` now answers `503` with `Retry-After` — not `401`, and with no lockout strike or `auth.login_failed` row — when a password cannot be verified because the auth store could not be read or the password changed while it was being checked; clients that treat every non-`401` as fatal should retry a `503`. New metrics: `yuzu_auth_password_changes_total{kind,result}`, `yuzu_auth_cfg_credentials_stale` and `yuzu_auth_credential_changed_during_verify_total`. New audit actions: `user.password_change`, `user.password_reset`.

No config or data migration is required.

## Behaviour change: per-OS plugin kill switch rows (#5294)

The plugin kill switch can now be narrowed per agent OS (`windows`, `linux`, `darwin`). The
`plugin_config_store` schema moves to v2 (`ALTER TABLE kill_switches ADD COLUMN os`). Existing
plugin and action rows read back unchanged, so nothing flips on upgrade.

- **Rollback.** v2 is an additive column and an older server starts on it without complaint (there
  is no schema-ahead guard). A server older than this change ignores every `<plugin>@<os>` row:
  per-OS OFF stops being enforced and its `GET` reports `enabled=true`.
- **Mixed versions.** An older replica applies `PUT .../kill-switch?os=<os>` as the PLUGIN-LEVEL
  row. `enabled=true` can therefore re-enable a plugin you stopped for the whole fleet, and
  `enabled=false` stops the plugin on every OS. Set per-OS rows only after every replica runs this
  build, and never write one from an older binary. After a rollback per-OS OFF rows stay stored
  but are not enforced: if the plugin must stay stopped, set its plugin-level OFF row. Find your
  rows in the `plugin_config.kill_switch.set` audit entries (`target_id`
  `<plugin>[.<action>]@<os>`) and confirm each with `GET ...?os=<os>` once every replica is back on
  this build.
- **Limits.** An agent whose OS is unknown or empty is never withheld. The OS is what the agent
  reports and is matched exactly (`windows`, `linux`, `darwin`). The MCP pre-dispatch dry run cannot
  see the per-OS layer. Remote agents (connected through another replica) rely on the presence
  snapshot.
- **Integrations.** MCP clients should key on `status`, tolerate unknown fields and re-fetch
  `tools/list`. `execute_instruction` has two new `status` values (`kill_switched_os`,
  `os_gate_unreadable`) and its output schema now requires `agents_kill_switched_os` in every
  zero-reach branch. The kill-switch REST responses gain additive `os` and `source` fields,
  and the `/api/command` response gains `withheld_kill_switched_os`.

## Behaviour change: protective actions exempt from plugin enablement

**What changed.** Five `plugin.action` pairs are now *protective*: the quarantine plugin's
`quarantine.quarantine`, `quarantine.unquarantine`, `quarantine.status` and `quarantine.whitelist`,
and the Guardian rule push `__guard__.push_rules`. No plugin-enablement gate refuses them any more:
not the per-plugin/action kill switch, not the per-OS kill switch (or its agent-presence read), not
the plugin-presence filter, and not a degraded plugin-config store. The set is closed. The four
quarantine actions are **newly** exempt; before this change only the containment gate exempted
them. Decision record: the 2026-10-12 update in [ADR-3005](../adr/3005-plugin-config-store.md).

A kill-switch row for one of these pairs is still accepted and displayed, but it is **kept and
inert**: it no longer stops dispatch. A plugin-level `quarantine` / `__guard__` row never stops the
plugin's protective actions either, and still gates any non-protective action the plugin declares
(none today: `quarantine` declares only the four, and `__guard__` dispatches only `push_rules`). A
`PUT` on one is audited with `protective_exempt=true` in the `plugin_config.kill_switch.set`
detail and logs a warning. If you stopped Guardian rule delivery by switching
`__guard__.push_rules` off, that stop **ends when you upgrade**: rules deploy on the next Baseline
deploy or heartbeat reconcile.

**Before upgrading.**

1. **Find held rows.** There is no list route. Search the audit log for
   `plugin_config.kill_switch.set` entries whose `target_id` is `__guard__.push_rules`,
   `quarantine.<action>` or the plugin-level `__guard__` / `quarantine`, each with an optional `@<os>`
   suffix. Each write leaves two rows (`attempted`, then `success` or `failure`) and a later
   `enabled=true` supersedes an earlier OFF, so take the latest `result=success` row per `target_id`.
   Confirm each with `GET /api/v1/plugin-config/<plugin>/kill-switch` at every layer: the
   plugin row, the action row (`?action=<action>`) and each `?os=windows|linux|darwin` variant, reading `source` in the response: it names the row that wins.
2. **Re-establish the stop through the rule lever first**, because the hold ends on upgrade. Disable
   the Guards (`PUT /api/v1/guaranteed-state/rules/<id>` with `{"enabled": false}`) or remove them.
   This is state-only: it disarms each Guard on the agent's next Baseline deploy or heartbeat
   reconcile, so the latency is the reconcile cadence. It disarms the rule; it does not freeze a push
   already in flight. No lever stops delivery while leaving armed Guards armed: the old switch did
   that, but disabling or removing a rule disarms it on the next reconcile. It needs `GuaranteedState:Write` (disable) or `GuaranteedState:Delete`
   (remove). `PluginConfig:Write` alone no longer stops anything, and a service-scoped token is
   denied on rule writes. A `quarantine.*` hold has no replacement switch: those actions are
   governed by their permission (`Security:Execute` on the catalogue rows) and any approval policy,
   not by enablement.

Also be aware of:

- **Rollback.** An older server has no exemption and honours stored OFF rows again, which can strand
  a quarantine release or hold back a rule push. Before rolling back, `PUT enabled=true` on every
  protective-pair OFF row you found (each layer and OS), then roll back.
- **Mixed versions.** During a rolling upgrade an older replica still honours a held row (or a degraded store or
  plugin-inventory gap) and refuses a protective dispatch while an upgraded replica delivers it, so the outcome depends on which replica serves the
  heartbeat or the reconcile. Lifting a hold arms rules fleet-wide on the next reconcile, including
  `enforce` rules, so expect a burst of arming rather than a gradual one.
- **Agents without the quarantine plugin.** The server no longer withholds a protective dispatch
  because the agent's reported plugin inventory lacks the plugin. `dispatch_confirmed` means the
  plugin registry **accepted the frame**; it is never proof of isolation. A
  device whose agent lacks the plugin answers its own "plugin not found", and
  `YuzuQuarantineEndpointUnconfirmed` can fire for it. Verify containment with `quarantine.status`,
  and upgrade agents before you rely on quarantine.
- **Integrations.** The kill-switch `GET` and `PUT` responses are unchanged: `enabled=false` for a
  protective pair is a stored row, not the dispatch decision. The `os_gate_unreadable`,
  `plugin_not_found` and `kill_switched_os` zero-reach causes are never produced for a protective
  action.
## Behaviour change: Guardian full_sync agent log lines and in-place `rule:` rows (#4415)

Three changes are live on every agent on upgrade, on both detection paths. The skip of healthy,
unchanged rules that motivated them runs only on the Spark path, which production does not enable
(`prefer_spark` is off); see the [Spark flip gate](../spark-flip-gate.md) AC-18.

- **Log line renamed.** `Guardian: full_sync cleared N prior rule(s)` is now
  `Guardian: full_sync removed N prior rule(s) absent from the push`, and it is not logged when no
  stored row is removed. Log rules or dashboards keyed on the old string go silent. Do not use the
  old line as a "a full push happened" marker.
- **New line on every full push.** `Guardian: full_sync preserved N rule(s) (skipped re-arm) ids=[...] more=M`
  is logged by every agent on every full push that reaches the end of its rule loop. Use it as the
  full-push marker instead. Legacy-path agents always log `preserved 0`.
- **Rows updated in place.** The agent's stored `rule:` rows are no longer cleared and reinserted
  on a full push: only the rows for rules the push omits are deleted, and a row whose bytes are
  unchanged is not rewritten. A crash after the omitted rows are removed and before the carried
  rules are rewritten leaves the previous rows for carried rules until the next push (a restart then
  re-arms those, including a rule the push had disabled or changed).
- **Rollback.** The row format is unchanged. An older agent reads the rows without complaint, and
  its own full_sync clear-and-reinsert restores the old write pattern. A newer agent rewrites any
  row whose bytes differ. There is no migration and a downgrade is safe.

## ⚠️ Docker Compose: copy `/etc/yuzu/certs` out of the server container before you recreate it (0.14.0 → 0.14.1, #5370)

**Who this affects.** Affected: a 0.14.0 Docker Compose stack whose server has no named volume on `/etc/yuzu/certs` while Postgres has one — `deploy/docker/docker-compose.yml` (the 0.14.0 README quickstart), `docker-compose.uat.yml`, `docker-compose.full-uat.yml`, `docker-compose.viz-uat.yml`, `docker-compose.demo.yml` used with `--keep`, any compose copied from them, and Compose Wizard output from before 0.14.1 in Plaintext mode, with 'Persist generated certs' unticked, or with named volumes off and an external Postgres. Not affected: `docker-compose.reference.yml` (which the README quickstart saves as `docker-compose.yml` since #5419) and `docker-compose.reference-gateway.yml` (their `certs` volume).

**Why.** The server keeps its internal CA, its default certificates and the secrets key-encryption key (KEK, `secrets-kek-v1.key`) in `/etc/yuzu/certs`. Since 0.14.0 the KEK is also registered in Postgres, whose data is on a volume. In the affected composes the key files sit in the container's own writable layer instead, so anything that replaces the container deletes them: an image upgrade, `docker compose down` then `up`, `up --force-recreate`, or an `up` after a change to the server's settings. Bumping only the image tag (or `YUZU_VERSION`) under the old compose file also triggers it. The next start then fails, on every restart, with:

```
SecretCodec::init() failed for the auth store bootstrap — kek_unresolvable: registered KEK 'secrets-kek-v1' does not resolve through the KekProvider
```

The 0.14.1 composes add a `server-certs` volume on `/etc/yuzu/certs`. Switching to them still recreates the container, so copy the files out first. Do this before anything else touches the stack.

How to run the blocks below:

- Run them in one terminal session, from the directory that holds your compose file (`deploy/docker` for the build-from-source stack). Later blocks use the `$OUT` variable that block 2 sets, so do not close the shell between them.
- If your compose file is not named `docker-compose.yml`, run `export COMPOSE_FILE=<file>` first. For `docker-compose.uat.yml`, also export `YUZU_VERSION=0.14.1` and every variable the file requires (for example `YUZU_GW_COOKIE`) before block 1.
- Paste one block at a time. The blocks contain no comments, so they paste the same way into bash and into zsh (including macOS zsh, which treats a pasted `#` line as a command).
- Block 2 ends with a line `OK: <path>`. **Go on only if you see that line.** Anything else, including no output at all, means stop.

**Block 1 — steps 0 and 1.** Step 0 checks that there is exactly one server container and that the keys are in it: the listing must show `secrets-kek-v1.key` (mode `-rw-------`) and `default-ca.key`. If it does not, do not go on; go to "If the server is failing with `kek_unresolvable`" below. Step 1 stops the server without removing it, because its container still holds the keys.

```bash
docker compose ps -a server
docker compose exec -T server ls -ln /etc/yuzu/certs </dev/null
docker compose stop server
```

**Block 2 — step 2: copy the directory out of the stopped container.** The copy goes to `$HOME/yuzu-keys-backup`, outside any checkout, owner-only (`0700` directory, `0600` file), and never over an existing file. `docker cp ... -` writes a tar stream, which keeps each file's owner and mode. The function keeps the archive only if `docker cp` succeeds, the whole archive reads back, it holds the CA certificate and key, and every KEK file in it is exactly 32 bytes (the size of a KEK). Otherwise it prints `STOP` and removes the partial file. It returns instead of exiting, so a failure leaves your shell open. It prints the CA fingerprint; note it. The archive holds the CA private key and the KEK: keep it as safe as the server itself.

```bash
BK="$HOME/yuzu-keys-backup"
yuzu_copy_out() {
  local cid out k n
  mkdir -p "$BK" && chmod 700 "$BK" || { echo "STOP: cannot create $BK"; return 1; }
  cid=$(docker compose ps -aq server)
  [ -n "$cid" ] && [ "$(printf '%s\n' "$cid" | wc -l | tr -d ' ')" = 1 ] \
    || { echo "STOP: expected exactly one server container, found: ${cid:-none}"; return 1; }
  out="$BK/yuzu-certs-$(date -u +%Y%m%dT%H%M%SZ).tar"
  ( umask 077; set -o noclobber; docker cp "$cid":/etc/yuzu/certs - > "$out.partial" ) \
    || { echo "STOP: copy failed; do not continue"; rm -f "$out.partial"; return 1; }
  tar -tf "$out.partial" > /dev/null 2>&1 \
    && tar -tf "$out.partial" | grep -qx 'certs/secrets-kek-v1.key' \
    && tar -tf "$out.partial" | grep -qx 'certs/default-ca.key' \
    && tar -tf "$out.partial" | grep -qx 'certs/default-ca.pem' \
    || { echo "STOP: the archive is incomplete; do not continue"; rm -f "$out.partial"; return 1; }
  for k in $(tar -tf "$out.partial" | grep -x 'certs/secrets-kek-v[0-9]*\.key'); do
    n=$(tar -xOf "$out.partial" "$k" | wc -c | tr -d ' ')
    [ "$n" = 32 ] || { echo "STOP: $k is $n bytes, not 32; do not continue"; rm -f "$out.partial"; return 1; }
  done
  mv -n "$out.partial" "$out" && [ ! -e "$out.partial" ] \
    || { echo "STOP: could not move the archive into place"; return 1; }
  tar -xOf "$out" certs/default-ca.pem | openssl x509 -noout -fingerprint -sha256
  OUT="$out"; echo "OK: $OUT"
}
yuzu_copy_out
```

If you have ever rotated the KEK, check that every version the database has registered has a file in the archive. Each number that `docker compose exec -T postgres psql -U yuzu -d yuzu -tAc 'select kek_version from secrets.kek_meta' </dev/null` prints needs a `certs/secrets-kek-v<N>.key` line in `tar -tf "$OUT"`.

**Step 3 — switch to the 0.14.1 compose file.** In a checkout, `git pull`. Otherwise download the file again into the SAME directory: a different directory is a different compose project, with its own empty volumes. For a compose of your own, add the volume yourself (see below). Regenerating a Compose Wizard compose is the same switch.

**Block 3 — steps 4 to 6: fill the new volume and recreate the server.** The function first checks the archive again, and refuses to touch anything unless `$OUT` names a non-empty archive that reads back in full and holds a 32-byte `secrets-kek-v1.key`. Step 4 then copies the archive into the `server-certs` volume. `docker compose run` creates the volume and mounts it in a one-off container, so the stopped server container is left alone. Step 5 checks that the server user can read a 32-byte KEK in the volume: the files must be owned by the uid the server runs as, 999 for `yuzu-server` and 1000 for `yuzu-server-chisel`. Only then does step 6 recreate the server. Each step that fails prints `STOP` and nothing after it runs. If you opened a new shell after block 2, replace `"$OUT"` with the path block 2 printed. For the build-from-source stack, add `--build` after `"$OUT"`; it is passed on to `docker compose up -d`.

```bash
yuzu_fill_and_recreate() {
  local p="$1" n
  shift
  [ -n "$p" ] && [ -s "$p" ] && tar -tf "$p" > /dev/null 2>&1 \
    || { echo "STOP: no complete archive at ${p:-(unset)}; nothing was changed"; return 1; }
  n=$(tar -xOf "$p" certs/secrets-kek-v1.key 2> /dev/null | wc -c | tr -d ' ')
  [ "$n" = 32 ] || { echo "STOP: the KEK in $p is ${n:-0} bytes, not 32; nothing was changed"; return 1; }
  docker compose run --rm --no-deps -T --user 0 --entrypoint tar server \
      -x -p --same-owner --numeric-owner -C /etc/yuzu/certs --strip-components=1 -f - < "$p" \
    || { echo "STOP: step 4 could not fill the volume; the server was not recreated"; return 1; }
  n=$(docker compose run --rm --no-deps -T --entrypoint sh server -c \
      'test -r /etc/yuzu/certs/secrets-kek-v1.key && test -w /etc/yuzu/certs && wc -c < /etc/yuzu/certs/secrets-kek-v1.key' \
      < /dev/null | tr -d ' \r')
  [ "$n" = 32 ] || { echo "STOP: step 5 found no 32-byte KEK the server user can read; the server was not recreated"; return 1; }
  docker compose up -d "$@" || { echo "STOP: step 6 failed"; return 1; }
  echo "OK: the server was recreated on the copied keys"
}
yuzu_fill_and_recreate "$OUT"
```

The chiselled `yuzu-server-chisel` image has no `tar`, so on it the function stops at step 4 and recreates nothing (the `docker compose run` there has already created the volume). Do steps 4 and 5 in a throwaway container instead, then step 6 by hand. `<project>_server-certs` is the volume's full name, which `docker volume ls` prints. The listing must show the files owned by uid 1000, with `secrets-kek-v1.key` 32 bytes:

```bash
docker run --rm -i --network none -v <project>_server-certs:/x/certs alpine tar -x -C /x -f - < "${OUT:?run block 2 first}"
docker run --rm --network none -v <project>_server-certs:/c:ro alpine ls -ln /c
```

Only if that listing shows `secrets-kek-v1.key` at 32 bytes, owned by uid 1000, recreate the server:

```bash
docker compose up -d
```

Run step 2 once. After step 6 the server container is a new one. If you re-run block 2 then, against a server that came back on the copied keys it only writes a second archive of the same keys; against one that came back without them it prints `STOP`. Either way the first archive is untouched.

Then confirm the server came back on the same keys. `docker compose logs server | grep secret_codec` shows `verified 1 registered KEK version(s)` (the count is of KEK versions, and the line repeats once per store that opens the codec), and this fingerprint matches the one block 2 printed:

```bash
docker compose exec -T server cat /etc/yuzu/certs/default-ca.pem </dev/null | openssl x509 -noout -fingerprint -sha256
```

Keep the archive as the keys half of a paired backup ([the KEK pairing rule](../ops-runbooks/auth-db-recovery.md#backup--the-kek-pairing-rule)) or `shred -u` it; never commit it.

For a compose of your own, the change is one volume on the server service:

```yaml
services:
  server:
    volumes:
      - server-certs:/etc/yuzu/certs
volumes:
  server-certs:
```

A new named volume takes its owner from the image's `/etc/yuzu/certs`, which the `yuzu-server` image creates owned by `yuzu`, so a fresh install needs no `chown`. The chiselled `yuzu-server-chisel` image creates that directory only from 0.14.1; on 0.14.0 and earlier chiselled images a new volume is owned by root and the server cannot write to it. The demo stack (`docker-compose.demo.yml`) runs a one-shot `server-certs-init` service that gives the volume to the server user, so it also works with older chiselled images.

**Rolling back.** To return to 0.14.0, change only the image tag/`YUZU_VERSION`; keep the 0.14.1 compose with its `server-certs` line. Reverting the compose file strands the keys on the undeclared volume, and `down -v` under the old file deletes Postgres while leaving the keys.

**If the server is failing with `kek_unresolvable`.** Work out which failure it is before you touch anything; several of them leave the keys intact, and only the last one means they are gone. These checks change nothing:

```bash
docker compose ps server
docker compose logs server | grep -m1 -E 'kek_unresolvable|provider_failure|kek_orphaned'
docker compose config | grep /etc/yuzu/certs
docker volume ls --filter name=server-certs
docker compose run --rm --no-deps -T --user 0 --entrypoint ls server -ln /etc/yuzu/certs </dev/null
```

A `STATUS` of `Restarting` means the server refuses to start. Then match the output against these cases, in order. They run the listing as root (`--user 0`), so a wrong owner shows as such instead of `Permission denied`.

- **(a) The compose lost the volume line** (a rollback, or an old file): `docker volume ls` lists `<project>_server-certs` for your project, but `docker compose config | grep /etc/yuzu/certs` prints nothing. The filter matches any project's volume, so check the `<project>_` prefix (the project name is the compose directory's name unless you set one). The listing is empty in this case too, because the old file mounts nothing there; that does not mean the keys are gone. Restore the line and run `docker compose up -d`. Never `down -v`.
- **(b) The files are there but owned by the wrong uid.** Give them to the server's uid (999 for `yuzu-server`, 1000 for `yuzu-server-chisel`), then run `docker compose up -d`:

  ```bash
  docker compose run --rm --no-deps -T --user 0 --entrypoint chown server -R 999:999 /etc/yuzu/certs </dev/null
  ```

- **(c) `provider_failure`:** the directory is not writable (a chiselled 0.14.0-or-older image's root-owned volume, or an `:ro` mount). Chown it to 1000:1000 or make it writable.
- **(d) The listing is empty: look for the keys on a dangling volume.** If the server's certs mount was an anonymous volume (`- /etc/yuzu/certs` with no name in front, as in Compose Wizard output from before 0.14.1 with named volumes off), `docker compose down` then `up` left the keys on the old, now unused volume and gave the new container an empty one. Both `docker compose down` and `down -v` leave such a volume in place, and `docker volume prune` deletes it, so do not prune. List the dangling volumes that hold KEK files:

  ```bash
  if docker image inspect alpine > /dev/null 2>&1 || docker pull alpine > /dev/null; then
    for v in $(docker volume ls -qf dangling=true); do
      docker run --rm --network none -v "$v":/c:ro alpine ls /c 2> /dev/null | grep -q '^secrets-kek-v' && echo "keys on volume: $v"
    done
    echo "search finished"
  else
    echo "STOP: the alpine image is not available, so the search did not run. Load it (docker load) and run this again."
  fi
  ```

  The search needs the `alpine` image; on a host without internet access, `docker load` it first. Go on only after `search finished`. Each `keys on volume:` line names a volume that holds keys; if there is none, case (e) applies. If there is more than one, they come from different installs: compare `docker run --rm --network none -v <volume>:/c:ro alpine cat /c/default-ca.pem | openssl x509 -noout -fingerprint -sha256` with the CA your agents trust. Switch to the 0.14.1 compose (step 3), copy the keys from that volume into the `server-certs` volume, then run `docker compose up -d`:

  ```bash
  docker compose run --rm --no-deps -T --user 0 -v <volume>:/from:ro --entrypoint cp server -a /from/. /etc/yuzu/certs/ </dev/null
  ```

- **(e) The listing is empty and none of the above applies:** the key files are gone. Recovery is below.

The chiselled image has no `ls`, `chown`, `cp` or `tar`. For it, run the same commands in a throwaway container on the volume, for example `docker run --rm --network none -v <project>_server-certs:/c:ro alpine ls -ln /c` (`docker volume ls` prints the full name).

Only case (e) means the key files are gone. Nothing inside the server can rebuild them.

- **You have a copy of the directory**, from a backup taken with the database (see [the KEK pairing rule](../ops-runbooks/auth-db-recovery.md#backup--the-kek-pairing-rule)) or an archive like the one in block 2. Switch to the 0.14.1 compose and fill the volume. From a `docker cp` archive, use block 3 as written. From a copy that has passed through your own filesystem (an unpacked backup, say), the files now belong to your user rather than to the server, so hand them back to it:

  ```bash
  tar -C <directory-containing-certs> -cf - certs | \
      docker compose run --rm --no-deps -T --user 0 --entrypoint bash server \
      -c 'tar -x -C /etc/yuzu/certs --strip-components=1 -f - && chown -R yuzu:yuzu /etc/yuzu/certs'
  ```

  Then run `docker compose up -d`. Restore the KEK and the `default-*` files together. If the KEK comes back but the CA files do not, the server refuses to mint a new CA over the one recorded in Postgres. Restore `default-*.{pem,key}` too, or follow the deliberate clean re-root in `docs/pki-architecture.md` "Operator runbook".
- **You have no copy.** Work through these in order.
  1. Dump the database first. It holds your audit log and configuration; the server cannot export it for you while it refuses to start. Keep the dump and query it offline, but never restore it into the new install (it registers the lost KEK).

     ```bash
     BK="$HOME/yuzu-keys-backup"; mkdir -p "$BK" && chmod 700 "$BK"
     ( umask 077; docker compose exec -T postgres pg_dump -U yuzu --format=custom yuzu < /dev/null \
         > "$BK/yuzu-final-$(date -u +%Y%m%dT%H%M%SZ).dump" ) && echo "dump written to $BK"
     ```

     With an external Postgres, run `pg_dump` against it with the server's DSN instead.
  2. **Do not delete rows from `secrets.kek_meta` to force a start.** The server then mints a new key under the same version number, every secret sealed under the lost key (webhook secrets, plugin and runtime config secrets, offload credentials) becomes permanently undecryptable with no error at boot, and a key file you later find cannot be used (#5421).
  3. This database cannot be brought back by any supported means. Every start checks each registered KEK and refuses. The one-shot modes `--mfa-reset` and `--break-glass-arm` run after that check, so they stop with the same `kek_unresolvable` error. What is gone: the CA private key, so every agent certificate it issued no longer chains and every agent must enroll again; and every secret sealed under the KEK, including TOTP enrolments, webhook signing secrets and the other secret columns listed in `docs/user-manual/server-admin.md` "Key management (secrets KEK)". Passwords and API tokens are hashed, not sealed, but they live in the same database.
  4. Start a new install. With the bundled Postgres, `docker compose down -v` deletes the Postgres volume along with the others. `down -v` does not reset an external Postgres: that database still registers the lost KEK, so a new install against it fails the same way. Give the new install a new, empty database. Then provision the admin account again, re-enroll your agents, and re-create your configuration.

## Behaviour change: the executions list fragment and MCP `summarize_working_set` (execution kind) use the fleet-read gate (#3526, #4753)

`GET /fragments/executions` (the dashboard executions list) and the `execution` kind of the MCP tool
`summarize_working_set` moved from a plain `Execution:Read` permission check onto the
management-group-aware fleet-read gate that `GET /api/v1/executions` already used. This is
hardening plus an admission change, not a fix for a leak: the old gate only admitted callers
holding a global grant, and those callers were never filtered. An author-run reachability probe
(not independently adjudicated; the JIT-elevated case was checked by code reading only) found nothing
served through the old gate that the unconfined `GET /api/v1/executions` would not serve the same
principal, with RBAC on or off (with RBAC off every non-service, non-engine caller whose tier allows it is unconfined by design; an engine principal is refused with 403)
(`docs/security-reviews/3526-confinement-reachability-probe-2026-10-05.md`). **There is no
admission change for a caller with a global `Execution:Read` grant, and nothing changes with RBAC
off for such a caller. What changes for every caller is the degrade and audit behaviour below,
plus one new prerequisite.**

- **RBAC off (the shipped default).** With RBAC off, both surfaces are unconfined for every authenticated non-service, non-engine caller whose tier allows it (an engine principal is refused with 403 with RBAC off),
  before and after the move to the fleet-read gate; a service-scoped token is refused
  (`403` on the REST and MCP twins, the permission note described under "Degraded store, fragment"
  on the fragment). Confinement on these two surfaces takes effect only with RBAC enforcement on.
- **Admission prerequisite (applies to every caller on these two surfaces).** The fleet-read gate
  needs both the authorization store and the management-group store open. When the RBAC store is
  not open, every caller except a JIT-elevated non-service session (which returns before any store
  check) gets a retryable `503` (`retry_after_ms` 5000) from the gate; when the management-group
  store is not open, every caller except an elevated session and an engine principal does (an
  engine principal is resolved from the RBAC store alone, and gets the `503` only when that store
  is not open). A global-grant administrator is included in both cases; the old plain gate never
  needed the management-group store. The REST and MCP twins show the `503` itself. On the dashboard
  fragment the gate still audits the refusal, but the response is replaced with an HTTP `200` note
  (`data-degraded="gate"`, see "Degraded store, fragment"), because the dashboard drops `4xx`/`5xx`
  bodies; `GET /api/v1/executions` keeps its real `503`.
- **Group-scoped-only operators** (an `Execution:Read` grant held only through a management group)
  previously got `403` from the **fragment** and now get a confined view: only executions that
  touched one of their agents or that they dispatched, with the counters and the error preview
  recomputed from their visible agents only. **`summarize_working_set` is different:** its first
  gate is still a plain `Infrastructure:Read` check, so a group-scoped-only operator still gets
  `403` there. Only a caller who holds a GLOBAL `Infrastructure:Read` plus a group-scoped
  `Execution:Read` is newly admitted to the confined execution view, and its narrative carries the
  same projected counts.
- **Service-scoped API tokens** get a confined view from `GET /fragments/executions` where
  they got `403`, but only when RBAC enforcement is ON, the `ITServiceOwner` role holds
  `Execution:Read` (the seeded default; see the next item) and the tag store is reachable. With RBAC
  enforcement off the gate still refuses it ("service-scoped tokens require RBAC to be
  enabled"), and a missing or degraded tag store is a retryable `503` (`retry_after_ms` 5000) on the
  REST twin; the fragment shows the matching note at HTTP `200`. In a
  normal deployment the tag store always exists (the server refuses to boot without it). On this
  fragment a service-scoped token sees only executions that touched an in-scope agent (see "Owner
  disjunct" below); its own just-dispatched execution stays invisible until an in-scope agent
  replies. `summarize_working_set` is unchanged for service-scoped tokens: it stays denied.
- **`ITServiceOwner` ceiling (applied by PR #5546, not by the executions-list move).** A service-scoped
  token is subject to the `ITServiceOwner` authority ceiling on the fleet-read gate. The executions-list move
  relies on that ceiling but does not add it. Its Breaking effect (`403` from
  `GET /api/v1/enrollment/pending-agents` for a service-scoped token), the retryable `503` for a
  failed ceiling read, the remediation and the audit search are in "Behaviour change:
  service-scoped tokens, the `ITServiceOwner` ceiling on the fleet-read gate, and
  `GET /api/v1/upload-grants` (#3526)" below.
- **Degraded store, fragment.** Every refusal or failure on `GET /fragments/executions` now renders
  an operator-visible note at HTTP `200`, because the dashboard drops `4xx`/`5xx` bodies and a
  refusal used to leave the panel on "Loading..." forever. There are three degrade kinds, set in the
  `data-degraded` attribute on `<div class="empty-state">`: `tracker` (the execution query or the
  agent-status read failed), `unavailable` (the fleet-read gate or the execution tracker is not
  wired, or a confined read has an empty principal: an administrator or a bug) and `gate` (the
  authorization gate refused with `503`: the RBAC store, the management-group store or the tag
  store is not open or unavailable, or the `ITServiceOwner` ceiling read is degraded; the text is
  "Executions unavailable (the authorization service could not be reached). Retry shortly."). A gate
  `403` (no `Execution:Read`, RBAC off for a service-scoped token, the ceiling denial, an engine
  principal without a grant) renders `<div class="empty-state" data-denied="true">` with "You do not
  have permission to view executions." and no reason text. A `401` for an unauthenticated request
  passes through unchanged. The gate still writes its audit row first, and no `Retry-After` header is
  sent with the note. Detect the notes with the `data-degraded` and `data-denied` attributes; none of
  them is the "No executions yet" text. **Monitoring blind spot:** `/fragments/executions` no longer
  answers `403` or `503` for these cases, so an HTTP-status monitor, a reverse-proxy access log or
  a synthetic check that treats `200` as healthy will not see them. The signals are the gate's audit
  rows (`auth.fleet_read_required` with `result=denied`), the panel text, and, for the ceiling case,
  `yuzu_server_rbac_read_degrade_total`. `GET /api/v1/executions` is unchanged and keeps its real
  `403`/`503`.
- **Approvals fragment and Executions filters answer 200 with a note.** `GET /fragments/approvals` now
  answers a `403` as `200` with `data-denied="true"`, a store failure as `200` with
  `data-degraded="store"` and an unknown `status` as `200` with `data-invalid="status"`; the
  executions fragment answers a malformed `definition_id` (default view too) or an unknown `status`
  with `200` and `data-invalid`. **Monitoring blind spot:** an HTTP-status monitor of these fragments
  sees `200` for those cases; detect the attributes instead.
- **Runbook, degrade note on the Executions panel.** `data-degraded="tracker"` means the execution
  tracker or its agent-status read failed: check `ExecutionTracker` warnings in the server log and
  PostgreSQL availability. `data-degraded="unavailable"` is a misconfiguration or bug branch (the
  fleet-read gate or the execution tracker is not wired, or a confined read has an empty
  principal), not a storage fault: it needs an administrator or a bug report, and a Postgres check
  will not clear it. `data-degraded="gate"` means the authorization gate could not decide. Look for
  audit rows `auth.fleet_read_required` with `result=denied` (detail `fleet read blocked:
  management-group store unavailable`, or the ceiling detail from the `ITServiceOwner` section
  below) and `yuzu_server_rbac_read_degrade_total` (it moves ONLY for the `ITServiceOwner`
  ceiling-read case: the management-group-store-unavailable refusal writes an audit row but does not
  move it). The server keeps no per-request access log. None of the notes clears on its own: the
  panel is loaded once, when the Instructions page reveals it (`hx-trigger="revealed"`, no polling),
  so after the cause is fixed reload the Instructions page (or reopen the Execution History
  section).
- **Degraded store, MCP.** `summarize_working_set` returns an error carrying `retry_after_ms`
  where it used to say the execution "was not found".
- **Empty confined page.** A confined caller who sees zero executions gets "No executions visible in
  your scope." instead of "No executions yet.", because out-of-scope executions may exist. Until an
  in-scope agent replies, a confined caller sees no trace of an execution they did not dispatch,
  because per-agent status rows are written as responses arrive; the panel can therefore show this
  text while an execution is in flight. MCP `list_executions` shows a confined caller only the
  executions they dispatched, not the in-scope executions of others (see
  `docs/user-manual/mcp.md`). The
  per-row status badge is still the execution's fleet-wide status while the counters are projected
  to the caller's agents (the same as the REST twin, SSE and the MCP detail view).
- **Owner disjunct.** Ordinary callers keep it: a principal's own dispatches are shown even when
  none of their agents replied, with the counters still projected. Service-scoped tokens do NOT get
  it on `GET /fragments/executions`. **Known limit (#5557):** a service-scoped token's session
  username is the account that minted it. On `GET /api/v1/executions`, `/{id}`, `/children`, MCP
  `get_execution_status`, MCP `list_executions`, legacy `/api/executions*`, the detail fragment,
  the SSE channel `/sse/executions/{id}` and `GET /api/v1/events`, a service-scoped token is
  therefore also shown executions its MINTER dispatched, even outside the service scope (counters
  projected, but id, definition, status and timing visible). Mint service tokens from an account
  that dispatches only inside the service scope. Executions the minting account has already
  dispatched stay visible to its service tokens on those surfaces, so a token minted from an
  account with unscoped history is exposed to that history.
- **Audit and SIEM.** For `kind=execution`, a CONFINED caller whose id is absent or outside scope
  now produces `action=mcp.summarize_working_set`, `result=denied`, detail
  `not found or outside caller's fleet-read scope: <id>` (the id is neutralised for `k=v` and
  CR/LF forgery and capped at 128 bytes; the `success` row's id gets the same treatment for EVERY `summarize_working_set` kind, not only `execution`). Only callers newly admitted by the move to the fleet-read gate can produce
  that row (the plain gate admitted only unconfined, global-grant callers, and confined callers got
  `403` before), so an existing rule keyed on `result=success` loses nothing for the callers it
  already saw; a rule keyed on `result=denied` for this action may now see the new callers. An
  UNCONFINED caller's absent id stays `result=success` (no denial occurred). The scope-collapse
  `denied` row (detail `not found or outside caller's fleet-read scope: <id>`) is written only for
  a CONFINED caller on `kind=execution`, so it is never written with RBAC off. Other `denied` rows
  on this action (tier refusal, permission-gate refusal, service-scoped default-deny) are separate
  and can occur regardless of RBAC state. The same neutralise-and-cap (128 bytes) now applies to
  the id in the `get_execution_status` `denied` rows and the `get_agent_details` `denied` and
  `failure` rows. A NUL byte in a `summarize_working_set` `kind=execution` id or a
  `get_execution_status` id is rejected with an invalid-params error before any lookup. The
  degraded-store errors of `get_execution_status` (agent-status read) and `list_executions` now
  carry `retry_after_ms`, like `summarize_working_set`.
  The `denied` row cannot tell a typo from an out-of-scope probe; that is intentional (no
  existence oracle). The narrative for an absent id is a success-shaped result, unlike
  `get_execution_status`, which returns an error for the same input.
- **Still unscoped.** `summarize_working_set` with `kind=fleet` or `kind=result_set` returns the
  whole-registry agent count (tracked in #4753, whose checklist, including `kind=fleet` and
  `get_fleet_posture_fast`, stays open; the executions-list move covers only `kind=execution`). The same
  whole-registry branch is also reached by `kind=execution` or `kind=agent` with an EMPTY id, or
  when the execution tracker is unavailable (not separately tracked). (`GET
  /api/v1/execution-statistics/agents` was listed here and is now confined; see "Behaviour change:
  per-agent execution statistics are confined to the caller's scope (#3526)".)

**Rollback.** Redeploy the previous binary. The plain `Execution:Read` gate returns, so
group-scoped-only operators go back to `403` on the fragment. The `visible_agents` filter is a
read-time parameter with no stored state, so there is nothing to migrate or clean up. Audit rows
already written with `result=denied` for `mcp.summarize_working_set` remain in the audit store.

## Behaviour change: service-scoped tokens, the `ITServiceOwner` ceiling on the fleet-read gate, and `GET /api/v1/upload-grants` (#3526)

Two chokepoints let a service-scoped API token reach more than the `ITServiceOwner` role allows (found
in a review of the fleet-read gate, #3526). Both now refuse it. This is a tightening for service-scoped tokens only;
non-service callers, elevated sessions and engine principals are unaffected.

**Breaking for service-scoped tokens, 1: `GET /api/v1/enrollment/pending-agents` now answers `403`.**
The management-group-aware fleet-read gate (`require_fleet_read`, ADR-0017) did not apply the
`ITServiceOwner` authority ceiling that `require_permission` applies to a service-scoped token. It now
does, through one shared helper (`authz::service_ceiling_check`): the token is refused (`403`,
"service-scoped token does not grant <securable>:<operation> (the ITServiceOwner role does not hold
it)", no `permission` field, audit `auth.fleet_read_required` / `denied`) unless that role itself holds
the pair, whatever its minter holds. `ITServiceOwner` does not hold `Enrollment:Read`, so a
service-scoped token that used to receive a pending-agent view narrowed to its tagged agents now gets
the `403`. **Remediation:** `Enrollment:Read` is intentionally NOT granted to `ITServiceOwner`; use an
Administrator-minted non-service token for that route. The cost is that this replaces a confined
credential with an Administrator-grade one, and there is no narrower option today: `Enrollment:Read` is
Administrator-only by default and custom-role authoring is not reachable through REST, MCP or the
dashboard yet.

**Breaking for service-scoped tokens, 2: `GET /api/v1/upload-grants` now answers `403`.** The route's
only gate evaluated the minter's username, so a service-scoped token inherited its minter's
`UploadGrant:Read` view (every grant, for a minter holding a global grant). It is now refused before any
grant is read (`403`, "service-scoped tokens may not list upload grants", no `permission` field, audit
`upload_grant.list.access_denied`). The MCP tool `list_upload_grants` already refused a service-scoped
token. **Remediation:** list grants with a non-service token. Non-service sessions are unchanged.

**The ceiling applies wherever a seeded `ITServiceOwner` permission is absent.** With the seeded
defaults `ITServiceOwner` holds every other pair the fleet-read routes pass, so nothing else changes
for `Execution`, `Response`, `Inventory`, `Infrastructure`, `Policy`, `GuaranteedState` and
`Workflow:Read`. No REST, MCP or CLI surface removes a seeded `ITServiceOwner` permission today, and a
direct database `DELETE` of the row is re-seeded at the next boot unless the pair is recorded in
`revoked_seed_defaults`, so a refusal on one of those pairs does not arise in a default deployment; the
rule is the safeguard for a pair removed through `RbacStore::remove_permission` (which records it) and for
any future surface that narrows the role.

**Failure behaviour.** A FAILED read of the `ITServiceOwner` role's permissions is a retryable `503`
(`retry_after_ms` 5000, an audit row with detail "RBAC read degraded resolving the ITServiceOwner
ceiling", and `yuzu_server_rbac_read_degrade_total` increments) rather than `403`, because an outage
is not a missing grant; it still fails closed (the dashboard executions fragment shows it as the HTTP `200` `data-degraded="gate"` note). This holds on the fleet-read gate and equally on
`require_scoped_permission`, which answered `403` for this failure before this change; only a
definitive deny is `403`. `require_permission` is different: a service-scoped token is refused there by
the default-deny allow-list whatever the ceiling read returns, so a retry could not succeed, and a
failed read answers the same default-deny `403` as a healthy one (no `retry_after_ms`, no
`yuzu_server_rbac_read_degrade_total` increment); only its audit row differs, ending with
"; ceiling read degraded". The ceiling read goes through the RBAC authz circuit breaker with a 250 ms acquire budget, so a degraded
store fails quickly and, once the breaker is open, requests are answered without touching the pool; an
open breaker is counted under the `pool_acquire_timeout` reason. The
breaker bounds how many requests wait, not how long an already admitted read holds its connection:
such a read can still wait up to the pool's `lock_timeout` (10 s default) or `statement_timeout`
(30 s default). On a dark network path (no reply at all) the wait is bounded instead by the pool's
`tcp_user_timeout` (10 s), which is confirmed on Linux, unconfirmed on Windows and a no-op on macOS, and
until two failures have returned, up to the pool size (16 by default, `--postgres-pool-size`) of these
reads can each hold a connection for that long. The breaker is the one operator permission checks use,
so ceiling-read failures can open it and an open breaker denies operators' cache-miss checks too (fail
closed). The breaker counts consecutive failures and any successful authz read, a ceiling read
included, resets the count, so a partial fault that lets the `role_permissions` read succeed while
other authz reads fail can delay the breaker opening for operators' cache-miss checks.

**New alert: `YuzuRbacBreakerOpen` (critical).** `docs/prometheus/yuzu-alerts.yml` now ships a per-replica
alert that fires when `yuzu_server_rbac_breaker_open` has stayed at `1` on a replica for 5 minutes. It
means authorization reads on that replica keep failing. While the breaker is open the replica refuses
(fail closed) the operator permission checks that miss its permission cache and sheds service-token
ceiling reads; cached decisions keep being served for at most about 5 seconds.
A breaker that closes again within 5 minutes does not page. Load the updated rule file if you maintain
your own copy of the shipped alerts.

**List-read A4 body.** The A4 body of a service-scoped token's `403` from the list-read gate no longer carries a `permission` field; clients should not read it.

**The sibling gates changed their budget.** `require_permission` and `require_scoped_permission` now
read the ceiling with the 250 ms authz acquire budget behind that shared breaker. Before, they acquired
with the 2000 ms `kReadTimeout` and were not breaker-gated, but the pool clamps a bounded acquire to
500 ms when it is already saturated at entry (`PgPool` `saturated_fast_fail`), so on a saturated pool the
wait was up to about 500 ms, not 2 s (a pool that saturated only after the call entered it was bounded
by the full 2 s). The change lowers that bound to 250 ms and, once the breaker is open, answers the
request without a pool touch.

**Rollback.** Downgrading the binary restores the previous behaviour for all of the above. The change
adds no schema and persists no state.

To find affected callers, search the audit log for `action=auth.fleet_read_required` with
`result=denied` and a detail containing "ITServiceOwner permission" (definitive deny, `403`) versus
"RBAC read degraded" (store fault, `503`), for the sibling gate `action=auth.scoped_permission_required`
with the same two details ("lacks ITServiceOwner permission" for the `403`, "RBAC read degraded" for
the `503`), and for `action=upload_grant.list.access_denied`. `action=auth.permission_required` never
carries the "RBAC read degraded" detail: a service token on a route behind the plain permission gate is
refused by the default-deny allow-list ("default-deny", `403`) whatever the ceiling read returns, and
during an outage of the `ITServiceOwner` read that row ends with "ceiling read degraded" (a healthy
default-deny row does not), so rows from `require_permission` routes with that ending mark the outage. For
`Execution:Read` the affected routes are the executions drawer's
`/fragments/executions/{id}/detail` fragment, the legacy `GET /api/executions*` routes,
`GET /api/v1/executions` with its `/{id}`, `/children` and `/api/v1/events` twins, and the MCP tools on
that gate that service tokens can reach at all. `POST /api/executions/{id}/rerun` and `/cancel` are not
affected: a service-scoped token is already refused at their first gate, `Execution:Execute`.
`kServiceScopeGlobalSafe` is not widened.

## Behaviour change: vuln_scan reports an unreadable config check as UNREADABLE and adds a summary row (#4961)

On Linux, `vuln_scan` (`scan`, `config_scan`) now reports a config file it could not read (`/proc/sys/kernel/randomize_va_space`, `/proc/sys/fs/suid_dumpable`, `/etc/ssh/sshd_config`, `/proc/mounts`) as `UNREADABLE|config|<title>|<path>: <cause>` instead of a HIGH/MEDIUM finding. `summary` always emits a seventh row, `summary|UNREADABLE|<n>`, and an absent `sshd_config` reads INFO "not applicable" with the SSH password row now emitted.

- **Affected:** scripts that index `summary` positionally or assert six rows; CEL or severity filters (a "no critical/high" policy passes a host it could not measure); dashboards keyed on MEDIUM counts on RHEL-family hosts where a non-root agent cannot read a mode-0600 `sshd_config`.
- **Recommended:** treat `UNREADABLE` as not assessed, and use `summary|UNREADABLE|<n>` as the coverage signal.
- No operator action is required, and rollback is safe (output strings only).

## Behaviour change: OTA refusal reason for an unreadable agent trust bundle (0.14.0 → 0.14.1, #5249)

- An OTA update refused because the agent cannot load its own update trust bundle (missing, permission-denied, or not a PEM certificate bundle) is now counted as `yuzu_agent_ota_signature_refused_total{reason="bundle_unreadable"}`, no longer `reason="untrusted"`.
- The agent logs it as `OTA update <version> REFUSED: the update trust bundle could not be loaded`. The grep string the 0.14.0 notes gave for #5196, `signature verification FAILED (untrusted chain)`, stops matching this fault; update any alert rule, dashboard or saved search keyed on the old reason or text. A genuinely untrusted signer still reports `untrusted chain` / `reason="untrusted"`.
- **New refusal, not a relabel: the trust bundle is now read bounded.** 0.14.0 loaded a bundle of any size from any file it could open. From 0.14.1 the agent refuses a bundle that is larger than 1 MiB, is not a regular file (a pipe, device or directory), or, on Windows, is held open by another process that does not allow shared reading (the agent does not wait for it). This applies to both `--update-trust-bundle` and `--plugin-trust-bundle`: an affected update is refused as `bundle_unreadable`, and an affected plugin as untrusted. On an agent with `--update-require-signature` or `--plugin-require-signature` this blocks every signed update or plugin until the bundle is fixed, and a refused OTA update cannot deliver the fix, so check before upgrading: the bundle must be a regular file of at most 1048576 bytes (`stat -c %s <path>` on Linux, `stat -f %z <path>` on macOS, `(Get-Item <path>).Length` on Windows). A code-signing anchor bundle is normally a few kilobytes.
- The update is still refused in both modes, and the heartbeat total `yuzu.ota_signature_refused` (so `yuzu_fleet_ota_signature_refusing_agents`) still includes it. Agent-only; no server change.
- The matching early warning, `OTA update trust bundle cannot be loaded as of this check`, is logged once by the OTA update checker when it first starts (after the agent first connects), and only when auto-update is enabled. It is not printed beside the startup `OTA update signature mode:` line.

## Behaviour change: DEX device score and management-group member reads now fail closed on a degraded read (#4855, #1762)

**Not a Breaking lead for the DEX routes and the management-group MEMBER-read path** — those already documented a `503` response before this release; what changes for them is when it fires, not the documented contract. **This does NOT hold for `GET /api/v1/management-groups/{id}`'s own GROUP-ROW read or its MCP twin `get_management_group`** (governance round-2, #1762): before this release, a degraded group-row read answered the SAME flat, undocumented `404 "group not found"` a genuinely nonexistent group id gets — there was no `503` contract for that case at all. This release adds a NEWLY DOCUMENTED, additive `503`/retryable error path for a degraded group-row read specifically; the `404` contract for a genuine not-found is unchanged. A client that already treats any `503` from these routes as retryable per the A4 contract needs no code change; a client that inferred "management group not found" purely from a `404` status code should note that `404` now unambiguously means "no such group" (never "could not tell") — narrower, not wider, than before.

**Operator-visible behaviour change (fail-closed reads).** Two previously fail-soft read paths now surface a degraded Postgres read as a retryable error instead of a healthy-looking or empty result:

- **Per-device DEX experience score (#4855).** `GET /api/v1/dex/devices/{id}` and MCP `get_dex_device_score` now answer `503`/a retryable MCP error when the per-device signal-summary read degrades, instead of the previous fabricated healthy score of 100 with no signals. The device-page DEX lens shows a "DEX store degraded." placeholder in the same case. `GET /api/v1/dex/overview` (and its dashboard/MCP twins) gains a new `unscored` field counting connected devices whose per-device score could not be computed — a non-zero `unscored` means `great`/`fair`/`poor`/`overall_experience` cover fewer devices than are actually connected, not a healthier fleet than reported.
- **Management-group reads (#1762).** The `/dex/perf/app` group-trend read (`GET /api/v1/dex/perf/group` and its dashboard/MCP twins), `/auto` VERIFY's before/after compare, and `GET /api/v1/management-groups/{id}` (+ MCP `get_management_group`) now report a member-lookup degrade as `503`/a retryable error, instead of rendering it as "0 members" or "no member reported". As of governance round-2, `GET /api/v1/management-groups/{id}` and `get_management_group` ALSO report a degrade in the GROUP ROW's own read the same way (`503`/retryable), instead of the flat `404` that previously made a store outage indistinguishable from a genuinely nonexistent group.

**Counters/alerts to watch during and after upgrade:** `yuzu_server_guardian_read_degrade_total` (alert `YuzuGuardianReadDegraded`; this release adds a new `source="guardian_rules"` value alongside the pre-existing `source="guardian_state"`, both now pre-seeded to 0 at boot across all three `reason` values) and `yuzu_server_mgmt_group_read_degrade_total` (alert `YuzuMgmtGroupReadDegraded`, now also counting the `get_members_checked` member-read degrade). A sustained non-zero rate on either during the upgrade window means the affected reads are answering retryable errors, not that devices or groups actually shrank.

No config or data migration is required.

## Behaviour change: devices that disconnect cleanly stay on `/hardware` as Offline (#5678)

**Not a Breaking lead:** no flag, wire format or API shape changes. In 0.14.0 a graceful agent disconnect deleted the device's `endpoint_state` row, so the device vanished from `/hardware` instead of showing as Offline. A graceful disconnect now clears only the row's presence session, so the device stays listed with its real last-seen time.

- **Migration v4 runs automatically** at server start. It is additive (`CREATE TABLE IF NOT EXISTS endpoint_state.retention_meta`), so rolling back to the previous server binary is safe: the old binary ignores the table.
- **Devices that disconnected under 0.14.0 were deleted and are not restored.** Each reappears on `/hardware` the next time it connects.
- **`/viz/fleet` and MCP `get_fleet_topology`** now also show a departed device, flagged stale, for 7 days, so `yuzu_viz_offline_hosts_total` rises after the upgrade.
- **Retention.** A row is deleted 37 days after its device was last seen (the 30-day roster window plus a 7-day margin). Each replica runs the prune hourly and deletes at most 12,000 rows per hour. The first pass runs about a minute after the server starts. On the first start after the upgrade it only records its clock anchor, so deletions begin with the next hourly pass; on every later start it already deletes; a large backlog inherited from an older release drains at that rate (100,000 rows in about 8 hours).
- **Decommission erases the row.** `DELETE /api/v1/sle/agents/{id}` deletes the device's `endpoint_state` row (#5682), so a decommissioned device leaves `/hardware`. A still-enrolled agent that heartbeats again re-creates it, so stop the agent first. A device that is never decommissioned ages out under the 37-day rule.

## Behaviour change: the DEX cohort floor is one device, and the Apps list fails closed

**Not a Breaking lead:** no flag or route is removed and no response field is renamed. Three operator-visible behaviours change.

- **The cohort floor is 1 (was 10).** A point, cohort or per-version figure with a single contributing device now publishes that device's exact CPU and memory aggregate on the un-audited DEX reads, including a cohort keyed by a per-device tag value (an asset tag, serial number or owner). No `agent_id` is emitted and the permission is unchanged (`GuaranteedState:Read`); the audited per-device drill is unchanged. The `floor` field those responses echo now reads 1.
- **The Prometheus cohort export carries one-device cohorts.** With `dex_cohort_export_key` set, a one-device cohort exports as `yuzu_fleet_perf_cohort_*{cohort=<tag value>}` on `/metrics`, governed by `/metrics` authentication (loopback is always unauthenticated; remote scrapes need any authenticated session, with no `GuaranteedState:Read` check, unless `--metrics-no-auth` is set) rather than `GuaranteedState:Read`. Choose keys whose values do not name a device or person. `yuzu_fleet_perf_cohort_clipped` can now rise on high-cardinality keys.
- **The Apps list answers `503` on a degraded read.** `GET /api/v1/dex/apps` answers `503` with `retry_after_ms: 2000`, and MCP `list_dex_apps` a retryable error, where they previously returned an empty list. Treat `503` as retry; it also answers `503` at once when four Apps reads are already running on that server (keep to four parallel calls and honour `retry_after_ms`; each refusal is counted on `yuzu_server_guardian_read_degrade_total{reason="concurrency_budget"}`, which trips the warning alert `YuzuGuardianReadDegraded` if it persists). The rows gain `distinct_devices_online` (an integer, `null` when no fleet source is wired); the share, rate and score are over the Windows devices online now, and the score is withheld as `offline_affected` while any affected device is offline (expect that on most multi-device applications of a fleet with laptops; use the share and rate until an offline-aware score is decided, #5894). The list is now Windows-scoped and keeps the 100 applications affecting the most devices (`apps_total` and `apps_truncated` report the cut); the Apps tab is unchanged.

No config or data migration is required.

## Behaviour change: a failed device-roster read is reported instead of shown as an empty fleet (#5531)

**Not a Breaking lead:** `GET /api/v1/hardware` and `GET /api/v1/hardware/{id}` already declared a `503` response; what changes is when it fires. (The new `400` on the record and sync routes, below, applies only to ids over 256 bytes or carrying a byte below `0x20`, which agent registration never accepts.) Before this release a failed read of the persisted device roster (pool timeout or query error) was shown as an empty roster.

- **`GET /api/v1/hardware`:** a failed roster read now answers `503` with `retry_after_ms` instead of a `200` with no rows. The Hardware list shows the "Hardware roster unavailable" banner instead of an empty table. REST consumers that treated `200` with no rows as "the fleet is empty" must treat `503` with `retry_after_ms` as "unknown, retry", never as an empty fleet.
- **`GET /api/v1/hardware/{id}`:** when the roster read failed and the device was not otherwise found (CI record readable-and-absent, no software, no tags) the route answers `503`, not `404`. A record that can still be served carries a new additive key `identity_state` (`found`, `degraded` or `absent`).
- **`GET /api/v1/hardware/{id}`, `POST /api/v1/hardware/{id}/sync` and the Hardware CI fragments:** a device id longer than 256 bytes or containing a byte below `0x20` now answers `400`. On `POST .../sync` and the fragments this replaces the permission check's `403`; on `GET .../{id}` it follows the route's `Inventory:Read` check (a caller without access still sees `401`/`403`) and replaces the scope `404` / roster `503`. Agent registration refuses both (the same 256-byte limit, and a byte below `0x20` through its enrollment check), so any id registration accepts passes and a registered device is not affected.
- **Hardware CI record (dashboard):** when the roster read failed and no CI record can be shown, the page says "Device roster unreadable" instead of "Device not found"; when a record can be shown, its Overview lens carries a "Device identity unavailable" note.
- **`GET /api/v1/viz/fleet/topology` and MCP `get_fleet_topology`:** still return the live fleet; the body now carries `offline_roster_degraded: true` when the durable offline-host read failed.
- **Observability:** the failure is counted on `yuzu_server_agent_presence_store_failed_total{op="query_stale_within"}` (once per failed read, not per cache window) and the audit rows record `result=failure`. A record served during a roster outage audits `result=failure`: SIEM rules keyed on `result=success` for `inventory.device.ci` / `inventory.device.software` must also key on `identity=roster unreadable` and `state=roster unreadable` (see the [audit log reference](audit-log.md)).

## Informational: internal-CA CRL publish/audit/observability follow-ups (HA WS-6, #4828–#4830)

No schema, config, or wire-shape change — this is documentation of behaviour that already
shipped with HA WS-6 slice 6.1 (`ca_crl_versions` migrations v3/v4, PR #4126) plus additive
audit/metrics coverage.

**Migration v3/v4 boot-time lock window (informational, applies to any upgrade crossing them).**
`ca_crl_versions` migration v3 (`revoked_count` column) and v4 (the `ca_issued_keep_revoked`
append-only trigger) each take a schema-level lock guarded by a 30 s `lock_timeout` — long
enough to outlast a legitimate in-flight CRL publish (which holds `SHARE ROW EXCLUSIVE` on the
same table for at most its own 5 s lock wait plus signing time), but a rolling upgrade that has
one replica already on the new schema while an older replica is still publishing can see up to
~30 s of the migrating replica's readers/writers queueing behind the older replica's lock. This
is a one-time cost on first contact with each version and does not recur.

**`ca.crl.published` is now audited on every publish path, not only operator revoke (#4829).**
Every CRL publish — the boot pre-publish, the leader-gated freshness re-publish, the
count-compare self-heal re-publish, and the two operator-triggered paths (revoke, subordinate-CA
import on REST/MCP/dashboard) — now writes a `ca.crl.published` audit row. The three paths with
no live operator request (boot, freshness, self-heal) audit under `principal=system`; every row
carries a `reason=` token (`startup`/`freshness`/`self_heal`/`revoke`/`import_chain`) so a
self-heal republish that resolves an earlier revoke-triggered failure leaves its own
`result=success reason=self_heal` row as the resolution, rather than the silence a prior gap left
here. See `docs/user-manual/audit-log.md`.

**New Prometheus counters (#4830):** `yuzu_server_ca_crl_publish_failure_reason_total{reason}`
(a bounded, closed cause breakdown alongside the existing
`yuzu_server_ca_crl_publish_failures_total`) and
`yuzu_server_ca_unpublished_revocation_check_failures_total` (the freshness pass's own
self-heal *check* failing — distinct from a publish failing outright). See
`docs/user-manual/metrics.md`. No operator action required; both are additive.

## ⚠️ Breaking: `--gateway-upstream` now refuses to start without gateway peer authorization

Affects you if the server runs with `--gateway-upstream` (or `YUZU_GATEWAY_UPSTREAM`). **The Linux package's systemd unit passes `--gateway-upstream` unconditionally**, so a Linux package install is affected even when you run no gateway: with your own certificates it will not start until you pin or drop the flag (see the table). The gateway-upstream service now requires an authorized gateway peer (an SPKI public-key pin, or an explicit acknowledgement). The decision is made at boot, before any listener is bound: a configuration that cannot be authorized makes the server exit non-zero with a message naming the flag to change. Nothing is silently downgraded, so check the steps for your deployment type **before** upgrading the server. Full reference: [Gateway upstream peer authorization](server-admin.md#gateway-upstream-peer-authorization).

**Check before you upgrade the server.** Read the arguments the server will actually start with, on the host, and apply the decision rule below.

| Deployment | Command |
|---|---|
| Linux package (systemd) | `systemctl cat yuzu-server \| grep -v '^[[:space:]]*#' \| grep -E -- '--(management-)?(cert\|key\|ca-cert)\|--no-tls\|--gateway-upstream\|YUZU_(CERT\|KEY\|CA_CERT\|GATEWAY\|INSECURE_GATEWAY)'` and, for the environment file, `grep -v '^[[:space:]]*#' /etc/yuzu/yuzu-server.env \| grep -E 'YUZU_(CERT\|KEY\|CA_CERT\|GATEWAY\|INSECURE_GATEWAY)'`. `systemctl cat` prints the unit and every drop-in, so a flag or an `Environment=` line added by a drop-in is covered. `YUZU_CERT`, `YUZU_KEY` and `YUZU_CA_CERT` are the environment names of `--cert`, `--key` and `--ca-cert`, so a unit with `Environment="YUZU_CERT=..."` plus `--gateway-upstream` refuses to start the same way a flag does. The `grep -v` drops comment lines: the shipped unit's comment block mentions every one of these flags, so without it the output is mostly comments (on the shipped unit the filtered output is the single `--gateway-upstream` line, and on the shipped `yuzu-server.env.example` it is empty) |
| Docker / Compose | From the directory of the compose file you actually use: `docker compose -f <file> config \| grep -E -- '--(management-)?(cert\|key\|ca-cert)\|--no-tls\|--gateway-upstream\|YUZU_(CERT\|KEY\|CA_CERT\|GATEWAY\|INSECURE_GATEWAY)'`, and the same two-stage `grep` (`grep -v '^[[:space:]]*#'` first) over any `env_file:` it names |
| Windows | `sc.exe qc YuzuServer` (the flags are in `BINARY_PATH_NAME`: look for `--ca-cert`, `--cert`, `--key`, the `--management-*` overrides, `--no-tls` and `--gateway-upstream`), and `dir "%ProgramData%\Yuzu Server\certs"`: a `grpc-cert.pem` or `ca-cert.pem` means your own gRPC certificates, a `gateway-peer-pin` file is a stored pin |

Decision rule (`--cert-san` and `--cert-group` matches do not count as certificates; the `--management-cert`, `--management-key` and `--management-ca-cert` overrides exist only as command-line flags, so no environment-file check can find them):

1. **No `--gateway-upstream` and no `YUZU_GATEWAY_UPSTREAM`:** not affected.
2. **`--gateway-upstream` and `--no-tls`:** add `--insecure-gateway-peer` (or `YUZU_INSECURE_GATEWAY_PEER=1`), or the server will not start.
3. **`--gateway-upstream` and your own certificates (`--cert`, `--key`, `--ca-cert` or their `YUZU_` variables), or any management override (`--management-cert`, `--management-key`, `--management-ca-cert`):** a `--ca-cert` given without `--cert` and `--key`, and any management override, make the gRPC listener credentials operator-supplied, so the automatic pin does not apply and the server refuses to start without a pin. One corner: the server compares the path (`server.cpp`, `agent_creds_are_default_files`), so a `--ca-cert` given without `--cert` and `--key` whose value is exactly `<ca-dir>/default-ca.pem` is the generated default, not your own, and the automatic pin still applies. You need a pin (`--gateway-peer-pin`, `--gateway-peer-pin-file` or their variables) **before** the upgrade. If you run no gateway, remove `--gateway-upstream` instead.
4. **`--gateway-upstream` and none of the above (generated default certificates):** nothing to set; the server pins its own gateway certificate.
5. **A pin and `--insecure-gateway-peer` together:** refused. Remove one.

A literal dry run (a `--check-config`-style command that evaluates this decision without starting the server) does not exist; it is listed as a deferred follow-up in the decision record, so use the check above.

**Back up the pin sources, and know what a restore does.** The pin is configuration the server reads once at boot, and it lives outside the database. Add these to your pre-upgrade backup: any explicit pin files (wherever you keep them; under the packaged unit they must be under `/etc/yuzu`), `/etc/yuzu/yuzu-server.env` (or your compose file and its env file), and on Windows `%ProgramData%\Yuzu Server\certs\gateway-peer-pin`. Restoring the server **without** the pin file makes it refuse to boot (a missing explicit pin source never falls back to the automatic pin). Restoring an **older** certificate directory under the automatic pin pins the old gateway key, so a gateway that presents a newer one is refused until the server's certificate directory and the gateway's certificate match again (then restart the server).

**What the service exposed before.** The service was reachable on every port the server's single gRPC server listens on, not only on `--gateway-upstream`. On the generated default certificates the agent port (`--listen`, default 50051) requests but does not require a client certificate, so a caller with no certificate could reach it. On the strict ports (management, gateway-upstream, and every port once you supply your own certificates) any holder of a client certificate signed by the install CA could, including an agent leaf. A caller whose `ProxyRegister` passed the handler's enrollment checks was also recorded as a trusted gateway peer by IP address, and under `--gateway-mode` that relaxes the Subscribe peer-IP binding for that address. This is exposure, not a demonstrated end-to-end exploit. The change closes the service to anything but a pinned gateway key; it does not change what the agent listener itself accepts.

**What it is now.** Every call must come from a TLS-authenticated peer whose certificate lists `serverAuth`, whose public key (SHA-256 of the SubjectPublicKeyInfo) is in the pin set, and which is inside its validity window. Pins are fixed at boot: changing them needs a server restart. There is no pin reload and no revocation read on this path.

| Your deployment | What happens | What to do |
|---|---|---|
| **Generated default certificates** (no `--cert`/`--key`, no `--management-*` overrides), TLS on, gateway presents the server's generated `default-gateway.pem` (the Docker reference gateway compose does; the Linux packages and the Windows installer with `/GATEWAY` also start the server on its generated certificates, so the same pin applies, but the gateway you deploy must present that certificate: the `yuzu-gateway` package's shipped configuration dials the upstream in plaintext and does not connect to a TLS server at all, see the comment block in `deploy/systemd/yuzu-server.service`) | The server pins `default-gateway.pem` automatically and boots. With `--cert-group` set it logs a warning that every process in the group holds gateway authority. | Check key custody: the gateway key file is the credential that authorizes a gateway. For a Docker reference-compose install, the shipped compose file now mounts only the public CA certificate into the agent container (a one-shot `ca-export` service fills a `ca-public` volume), and pulling the new file changes nothing until the agent container is recreated: from `deploy/docker` run `YUZU_ENROLL_TOKEN=<token> docker compose -f docker-compose.reference-gateway.yml up -d` for the **whole** stack (the file refuses to start without `YUZU_ENROLL_TOKEN`; any value works for an agent that is already enrolled), not `up -d server gateway`, which leaves a running agent on its old mounts. If an agent container ever held the old mount, treat the gateway key as exposed: replace it and withdraw its pin (changing mounts cannot invalidate a copied key). A gateway on another host that does **not** present `default-gateway.pem` is denied until you pin its key. |
| **Your own certificates** (`--cert`/`--key`/`--ca-cert`), gateway connected over TLS | **Refuses to start** until a pin is configured. | Compute the pin with `openssl x509 -pubkey -noout -in gw.pem \| openssl pkey -pubin -outform DER \| openssl dgst -sha256 \| awk '{print $NF}'` and pass `--gateway-peer-pin <hex>` (or `--gateway-peer-pin-file <pem>`; env `YUZU_GATEWAY_PEER_PINS` / `YUZU_GATEWAY_PEER_PIN_FILE`). On Windows, which has no `awk`, prefer `--gateway-peer-pin-file <cert.pem>` with the gateway's leaf certificate: the byte pipeline is not documented for Windows PowerShell 5.1, whose text pipeline may corrupt the binary DER, and a wrong-looking hash is the commonest mistake (see "Lockout diagnostic" in the operator guide). The gateway certificate must carry `serverAuth` and `clientAuth`. |
| **HTTPS on generated defaults but gRPC on your own certificates** | Treated as your own certificates: no automatic pin. | As the row above. |
| **Plaintext** (`--no-tls`) with a gateway | **Refuses to start.** `--no-tls` is not an acknowledgement. | Add `--insecure-gateway-peer` (env `YUZU_INSECURE_GATEWAY_PEER=1`). Peer authorization is then **disabled on every port the service is reachable on**, with a boot error line and a boot audit row. Never combine it with a pin flag: that also refuses to start. |
| TLS on but no client CA (`--insecure-skip-client-verify`) | **Refuses to start**: no pin could ever match. | Supply `--ca-cert`, or use `--insecure-gateway-peer` on a development rig. |
| **Linux packages** (systemd unit) | The shipped unit passes `--gateway-upstream` unconditionally and runs TLS on generated certificates, so the automatic pin applies and it boots. An install that gave the server its **own** certificates refuses to start unless a pin is set, **even when it runs no gateway**. The deb `postinst` only enables the service, so the failure surfaces at the next restart or reboot; the RPM restarts the service on upgrade, and systemd stops retrying after 3 failed starts in 60 seconds. The RPM `%pre` and the deb `preinst` of this release print an advisory warning on stderr during an upgrade when `/etc/yuzu/yuzu-server.env` or a `yuzu-server.service` override under `/etc/systemd/system` shows your own certificates with `--gateway-upstream` and no pin or acknowledgement; it never fails or changes the upgrade, it reads only those files, and the check above remains the authority. | With your own certificates, set the pin in `/etc/yuzu/yuzu-server.env`. If you run **no** gateway, omit `--gateway-upstream` with a drop-in (the literal block is under the table); a package upgrade overwrites the unit file, a drop-in survives. A `--no-tls` drop-in now also needs `--insecure-gateway-peer`. Pin files must be readable by the `yuzu` user and live outside `/home` and `/tmp` (`ProtectHome` and `PrivateTmp` hide them): keep them under `/etc/yuzu`. |
| **Windows installer** | `/GATEWAY` with `/NOTLS` adds `--insecure-gateway-peer`. `/GATEWAY` with generated certificates needs nothing, but a gateway on **another machine** must either present the server's generated `default-gateway.pem` or have its key pinned. `/GATEWAY` with your own gRPC certificate and key needs a pin the first time: the installer refuses an upgrade or install that would start gateway mode on your own certificates with no pin, before anything is changed. | Give `/GATEWAY_PEER_PIN_FILE=<cert.pem>` (preferred: the leaf certificate only, because a chain file pins every block) or `/GATEWAY_PEER_PIN=<64 hex>`; the two are mutually exclusive, and the interactive wizard has no pin page, so a pin is given on the command line only. The installer stores it as `gateway-peer-pin` in the `certs` folder under the data directory (`%ProgramData%\Yuzu Server\certs`) and, whenever gateway mode is selected, TLS is not skipped and that file exists, passes `--gateway-peer-pin-file` for it on every run, so the pin survives later upgrades. With `/NOTLS` the file is kept but not passed, because the server refuses the acknowledgement together with a pin, and `/GATEWAY /NOTLS` given **together with** a pin parameter is refused by the installer with nothing changed. A refused silent install exits with code 7 and the reason is only in the `/LOG=` file on a line starting `PrepareToInstall:` (deployment tools that report only the exit code do not show the reason); the existing service is left as it was. If you later revert the install to the generated default certificates, delete `certs\gateway-peer-pin`: the stored pin keeps being passed and replaces the automatic pin, so the generated gateway certificate would be refused. The installer checks that `/GATEWAY_PEER_PIN` is exactly 64 hexadecimal characters and applies only cheap checks to a pin file (it exists, is not empty, has no NUL byte); the server validates the contents when it starts. Giving either parameter again replaces the stored pin, so rotation with an overlap needs a multi-entry pin file. A service command line edited by hand is rebuilt by the installer on every run, so do not rely on it. |
| **Compose wizard output** (plaintext stacks) | A stack generated by an earlier wizard revision refuses to start after an image pull: its server runs `--gateway-upstream` with `--no-tls` and no acknowledgement. | Add the variable to the server's `environment:` block in that block's own style (the wizard's list form `- YUZU_INSECURE_GATEWAY_PEER=1`, or `YUZU_INSECURE_GATEWAY_PEER: "1"` in a mapping block; compose rejects mixing the two), or regenerate the stack: the wizard now emits the list-form variable for a gateway stack without TLS. |

The repository's own plaintext rigs already carry the acknowledgement in this release. Four scripts and three compose files pass it as a flag: `scripts/start-stack.sh`, `scripts/start-UAT.sh`, `scripts/win-start-UAT.sh` and `scripts/integration-test.sh` (which passes it in both its plaintext and its `--tls` branch, so neither branch exercises a pinned gateway hop), and `deploy/docker/docker-compose.full-uat.yml`, `docker-compose.sanitizer-uat.yml` and `docker-compose.viz-uat.yml`. The two compose files that pull published release images, the root `docker-compose.uat.yml` and `deploy/docker/docker-compose.demo.yml`, set it as the environment variable `YUZU_INSECURE_GATEWAY_PEER`, as does the compose wizard's plaintext gateway output. `deploy/docker/docker-compose.reference-gateway.yml` runs TLS on generated certificates and needs no acknowledgement. `scripts/ci/qa-stack.sh` launches no server of its own: it runs that reference-gateway compose on published release images, so the automatic pin applies and it needs no acknowledgement either (only a comment changed there). `deploy/config/docker.env.example` and `deploy/config/yuzu-server.env.example` document the new variables and `deploy/systemd/yuzu-server.service` carries a comment block for the unit. If you keep a modified copy of any of these files, carry the change over by hand. Release images that predate the acknowledgement ignore the environment variable, so with such an image the variable is harmless; to get the new behaviour set `YUZU_VERSION` to a release that includes it, or rebuild the images locally (a stale local image does not have it either).

**Linux package, own certificates, no gateway.** The shipped unit passes `--gateway-upstream` unconditionally. Run `systemctl cat yuzu-server` to see the unit you actually have (a local edit may differ), then run `systemctl edit yuzu-server` and enter the following, which first clears the inherited command and then repeats it without `--gateway-upstream` (this is the shipped `ExecStart` of `deploy/systemd/yuzu-server.service` minus that one line; keep any other arguments your unit carries):

```ini
[Service]
ExecStart=
ExecStart=/usr/local/bin/yuzu-server \
    --listen 0.0.0.0:50051 \
    --web-port 8080 \
    --data-dir /var/lib/yuzu
```

Then `systemctl restart yuzu-server`. If you do run a gateway, leave the unit alone and set the pin in `/etc/yuzu/yuzu-server.env` instead.

**Rotating or withdrawing a pin is a restart.** Pins are read once at boot. To rotate, list the old and the new pin together, **in the same source** (a command-line pin makes the matching environment variable ignored, not merged), on every replica, roll the replicas, switch the gateway (it presents a new certificate only after it redials; a gateway redials after its connection drops and reads its certificate and key from the configured files when it does, inferred from reading the grpcbox code and not tested), confirm `yuzu_server_gateway_peer_denied_total{reason="not_pinned"}` stays flat on every replica, then remove the old pin and roll again. To withdraw a key, remove its pin from every source and restart every serving replica. Revoking a certificate serial in the CA store does not remove a key pin. The procedure, including what to do after a refusal window, is in [Gateway upstream peer authorization](server-admin.md#gateway-upstream-peer-authorization).

**After a refusal window, work out which side the cause was on first.** A gateway that was refused (gRPC status 16) does not retry a refused `NotifyStreamStatus`, so a session whose CONNECTED notice was refused can stay unplaced. The step-by-step runbook, with a verification after each step, is in [Gateway upstream peer authorization](server-admin.md#gateway-upstream-peer-authorization); in short, there are three cause classes.

- **A, the cause was on the server side** (a wrong or missing pin or acknowledgement, other server configuration; the gateway's certificate is unchanged): restart the serving replicas with the corrected configuration and do not restart the gateways first, unless the placement check below fails (class C), because on agents without the #5183 fix (in no release yet) a gateway restart leaves released agents wedged. A gateway that includes the #1197 heartbeat-verdict consumer (#5383) recovers through its replay path, after at most one breaker open period (300 s at most, and only if it opened), the agent heartbeat interval and the replay drip. To roll the change back, revert the pin or acknowledgement on every replica and restart the replicas (the pin set is fixed at boot). Verify with three separate checks: `sum(yuzu_gw_agents_current) - sum(yuzu_agents_connected{job="yuzu-server"})` (summed across all gateway nodes and all replicas; the server gauge also counts direct agents and counts registration, not placement), no rise in `yuzu_gw_upstream_rpc_errors_total{rpc_name="notify_stream",code="16"}` or `yuzu_gw_upstream_notify_dropped_total` over the window, and a successful read-only command to a sample agent, confirmed by that agent's own result (the exact request and the limits of the check are in the runbook). Agreeing counts alone do not prove placement.
- **B, the cause is on the gateway side** (its certificate expired or was renewed, its key rotated, renaming `default-marker.json` minted a new leaf, or it points at the wrong certificate): the gateway presents its current files only when it redials, and a server restart or any dropped connection forces a redial, so first check whether it already has: the raw counters `yuzu_server_gateway_peer_denied_total` and `yuzu_gw_upstream_rpc_errors_total{code="16"}` have stopped rising (read them twice, a minute apart, not through `increase()`: the gateway series is not pre-seeded), no new `spki=` denial line appears in the server log, and the certificate file the gateway is configured with has the expected SPKI prefix. A redial can still present the previous certificate for about 2 minutes after the files change (the Erlang ssl PEM cache cleans every 120 s; measured on OTP 28.4.2 with a stub by a reviewer, not on a Yuzu gateway), so wait about 2 minutes. A same-key renewal needs no server restart. Restart that gateway node, one node at a time, only if denials continue and its agents can take the disconnect: a gateway restart disconnects every agent the node holds, and unless the agents run a build with the #5183 fix (in no release yet) released agents stay wedged afterwards; see [Gateway](gateway.md), "What happens when the server restarts". Plan renewals before `notAfter`, inside a maintenance window.
- **C, placement loss is suspected after a refusal window** (notify errors or drops rose, or a sample agent is unreachable although the counts agree): restart the agent service on the specific unreachable agents, which [Gateway](gateway.md) records as the observed fix. Restart the gateway node, one node at a time, only if many agents behind one node are affected and the class A checks still fail after the timing allowances in the runbook, with the same #5183 caveat: unless the agents run a build with that fix, released agents stay wedged afterwards. The gateway restart is inferred from the code and untested.

**Certificate expiry is class B.** A gateway whose connection outlives its certificate's `notAfter` is refused on every call and does not redial by itself, so renew the certificate before `notAfter`, inside a maintenance window, and follow class B above to tell whether the gateway has already redialled.

**Mixed replicas (HA).** Give every replica the same pin set (on the generated defaults each replica pins its own `default-gateway.pem`, so if you ever give replicas different certificate directories, supply the same explicit pin on all of them). Compare the pin prefixes in each replica's boot log line. Roll the replicas first; a gateway needs a restart afterwards only if the cause is on the gateway side and denials continue (class B above), because unless the agents run a build with the #5183 fix (in no release yet) released agents stay wedged after one. While replicas run different versions an old replica admits calls that a new one refuses.

### Rollback / temporary exception

Rolling back is a binary-only change: gateway peer authorization has no schema or store change. But the **previous binary has no gateway peer authorization at all**, so a rollback is itself a risk acceptance of the same kind as `--insecure-gateway-peer`. Record who accepted it, the date, **and the date by which it will be remediated** (a pin in place on the new binary), and schedule that work rather than leaving the old binary running.

**Remove the new flags BEFORE rolling the binary back.** An **older** binary rejects an unknown flag at startup (a command-line parsing error) but ignores an unknown environment variable, so a configuration that passes `--insecure-gateway-peer`, `--gateway-peer-pin` or `--gateway-peer-pin-file` on the command line fails to start on the old binary, while the same settings supplied as `YUZU_INSECURE_GATEWAY_PEER`, `YUZU_GATEWAY_PEER_PINS` or `YUZU_GATEWAY_PEER_PIN_FILE` are simply ignored. Remove the flags wherever they live:

- **Windows service.** The command line is the service's `ImagePath` (`HKLM\SYSTEM\CurrentControlSet\Services\YuzuServer`), which the installer writes. Reinstall with the previous version's installer rather than editing the registry value by hand. The previous installer does not know the stored `certs\gateway-peer-pin` file and never passes it.
- **Linux package.** The unit file or the drop-in under `/etc/systemd/system/yuzu-server.service.d/`; `/etc/yuzu/yuzu-server.env` carries only environment variables, which an old binary ignores.
- **Compose files and local start scripts.** The seven flag-based rigs (`docker-compose.full-uat.yml`, `docker-compose.sanitizer-uat.yml`, `docker-compose.viz-uat.yml`, `scripts/start-stack.sh`, `scripts/start-UAT.sh`, `scripts/win-start-UAT.sh`, `scripts/integration-test.sh`): use the previous revision of each file, because the new revision passes a flag the old binary rejects. The environment-based files (`docker-compose.uat.yml`, `docker-compose.demo.yml`, wizard output) need no change, and neither does `scripts/ci/qa-stack.sh`, whose only change is a comment.
- **Reference gateway compose.** The previous revision of the compose file mounts the whole certificate volume into the agent container again. That restores the key exposure described above; do not roll the compose file back without the same risk record.

To keep a new binary running while you fix a pin, `--insecure-gateway-peer` is an exception, not a fix: it disables peer authorization on every port the service is reachable on. Treat it as a time-boxed risk acceptance too: record who accepted it, the date and the remediation date, put the pin in place, and remove the flag. On a TLS server with a client CA the exception is reported as `yuzu_server_gateway_peer_authz_mode{mode="insecure_ack_tls"}` and raises `YuzuGatewayPeerAuthzDisabledWithTls`; every start with it writes a `server.gateway_peer_authz_disabled` audit row.

New flags and series: `--gateway-peer-pin`, `--gateway-peer-pin-file`, `--insecure-gateway-peer`; `yuzu_server_gateway_peer_*` (see [Metrics](metrics.md)).

## ⚠️ Breaking: gateways fronted by an HTTP/2-terminating proxy or mesh sidecar (#3869)

Affects you only if you run the Erlang gateway and agents reach it through something that terminates
HTTP/2: an HTTP/2-aware reverse proxy (for example nginx `grpc_pass`), an L7 load balancer, or a
service-mesh sidecar. Agents that connect to `:50051` directly, or through an L4 / TLS-passthrough
path that keeps one TCP connection per agent, are not affected by the proxy requirement; see Older
agents and the registry restart note below.

**Minimum agent version.** An agent rejected by the gateway recovers by re-registering through its
`NOT_FOUND` handling. That logic exists from v0.13.0, but the released v0.13.0 and v0.14.0-rc6 agents
wedge in their reconnect path with default settings (bug #2182, fixed by PR #5183, which is in no
release yet) and recover only with `--no-auto-update` (observed with v0.13.0 and v0.14.0-rc6), or on a
build that includes the fix. v0.12.0 never recovers by itself (observed; older versions were not tested). Upgrade the
agents first, then the gateway, using a build that includes the #2182 fix once released; until then,
restart an agent that stays rejected (restarting the agent service re-registers it). Agents that do
not connect through the gateway are not affected by this requirement.

The gateway now admits an agent `Heartbeat` only on the HTTP/2 connection that opened the session's
`Subscribe` stream, and only for a session that gateway node holds. A heartbeat that arrives on any
other connection is answered `NOT_FOUND` (`unknown session`), counted and not forwarded.
HTTP/2-terminating proxies are unsupported: they may cause repeated heartbeat rejection or share
gateway-side connections across agents, removing the per-agent connection separation this check
requires. Observed in a test with nginx `grpc_pass` in front of two agents: every heartbeat was
rejected, agents still enrolled and received commands, no heartbeat reached the server and the
server's online count flickered; an L4 TCP forwarder (nginx `stream`) caused no rejections. Each rejection raises
`yuzu_gw_heartbeat_session_mismatch_total{event="security"}` or `yuzu_gw_heartbeat_rejected_total{reason}`
and appears in a rate-limited gateway summary log line (the `connection_mismatch=` count). The
agent-facing message is the same `unknown session` for every reason, so diagnose from the counters
and that log line.

**Check before upgrading.** Look for an HTTP/2-terminating hop between the agents and `:50051`
(reverse proxy, L7 load balancer, mesh sidecar). If there is one, move agents to an L4 or
TLS-passthrough path first, or exempt `:50051` from the proxy. Also check the agent versions of
your fleet (the Hardware list at `/hardware` shows each device's agent version) and upgrade every
agent older than 0.13.0 that connects through the gateway before you deploy the new gateway, and
plan to restart any released 0.13.0 or rc6 agent that stays rejected; see Older agents below.

**Restart requirement.** Deploy the new gateway with a restart. The session index is created when the
gateway registry starts and hot code upgrade is not supported for this change. A node that had the
new code loaded without a restart has no index table, rejects every heartbeat as
`registry_unavailable`, and reports `sessions_index` in `/readyz` (503 while the table is missing).

**Rollback.** Redeploy the previous gateway release. The only new state is the in-memory session index,
and there is no wire, agent or server change, so nothing needs migrating; agents with the reconnect
fix re-register on their own (released agents may need a restart, see the next paragraph for older
agents), and a rollback removes the connection check. This path
is derived from the change and was not run.

**Older agents.** A rejected agent recovers by re-registering through its `NOT_FOUND` handling
(escalating cooldown, 2 s doubling to a 300 s cap). That logic exists from v0.13.0 (checked in the
agent source), but in the released v0.13.0 and v0.14.0-rc6 agents it is blocked by bug #2182 (the
update-check thread join wedges the reconnect teardown; inferred cause), fixed by PR #5183, which is
in no release yet. With default settings those agents log `(#1894)` and `Heartbeat thread stopped`
and then never re-register (observed, 19 minutes, reproduced on a second agent); with
`--no-auto-update` they re-registered 20 to 21 s after a gateway registry restart (observed with
v0.13.0 and v0.14.0-rc6; it is a command-line flag with no environment variable). Agent v0.12.0 only logs `Heartbeat failed` and never re-registers by itself (older versions were not tested)
(observed with v0.12.0, 29 failures in 14.5 minutes with default settings; a `--no-auto-update` run was watched for only about 2 minutes and behaved the same; older than v0.12.0 was not tested), so for persistent missing state they stay
rejected until restarted or upgraded (such agents were still counted online by the server's `/health` `agents.online` in the rig, so check the rejection counters and the agent log, not the online count; a heartbeat that falls in the short gap between the session
leaving the pending table and its agent process registering can succeed later without
re-registration). Upgrade the agents first, then the gateway, with a build that includes the #2182
fix once released; until then, restart an agent that stays rejected (restarting the agent service
re-registers it). Agents that do not connect through the gateway are not affected. This matters
only when heartbeats are rejected, which happens in four cases:

- a topology that breaks the one-connection assumption;
- a gateway running without the session index;
- a gateway registry process restart or crash while agent connections stay up. The registry
  recreates its tables empty, so every heartbeat for the agents it held is rejected until they
  re-register. A node failover that leaves the session not held by the surviving node is expected
  to behave the same way (inferred, not tested);
- for released agents, a gateway process restart. In a graceful SIGTERM and restart run the
  released agents tested (v0.14.0-rc6, v0.13.0, v0.12.0, default settings) did not notice the lost
  `Subscribe` stream, sent their next heartbeats over a re-established channel to the new gateway
  and got `NOT_FOUND`; v0.14.0-rc6 and v0.13.0 then wedged (no re-register through the 1 minute
  40 s the run watched them) and v0.12.0 kept logging failures. The agent built from the branch
  tree noticed the lost stream and re-registered in 11 to 12 s with no rejections (observed).
  Restart released agents after a gateway restart if they stay rejected.

The registry-restart recovery in 17 to 37 s was observed with agents built from the branch tree
(version 0.14.0, which includes the #2182 fix). Released agents were observed as described above.

See [Heartbeat admission](gateway.md#heartbeat-admission) for the supported topologies, counters and
runbook.

## ⚠️ Breaking: `GET /api/v1/openapi.json` now requires authentication (#2057)

The OpenAPI spec endpoint used to be public — any unauthenticated client could
fetch it to learn the REST surface. It now gates `Infrastructure:Read`, the
same permission the MCP `yuzu://openapi` resource twin already required, so
the two surfaces agree.

**Breaking for pre-auth tooling.** A script, health-checker, or API-client
codegen step that fetched the spec before logging in now gets `401` instead
of the document:

```json
{"error":{"code":401,"message":"unauthorized"},"meta":{"api_version":"v1"}}
```

**What to do.** Fetch the spec with a session cookie or an API token, same as
any other `/api/v1/*` route:

```bash
# Session cookie (dashboard-style login)
curl -c cookies.txt -X POST http://localhost:8080/login \
    -d "username=admin&password=<password>"
curl -b cookies.txt http://localhost:8080/api/v1/openapi.json

# API token
curl -H "Authorization: Bearer <api-token>" \
    http://localhost:8080/api/v1/openapi.json
```

## Agent OTA pulls are now bounded per peer (#913, #911) — behaviour change

`DownloadUpdate` is now admitted through a per-peer gate. A refused pull returns
gRPC `RESOURCE_EXHAUSTED`; a transfer exceeding `--ota-transfer-deadline-secs`
(default 900) or `--ota-chunk-write-deadline-secs` (default 30) returns
`DEADLINE_EXCEEDED`. Agents retry on their normal update interval, so no update is
lost — but the first fleet-wide update after upgrading can take substantially
longer than before, and on one deployment shape it can take days.

**Check this before your first post-upgrade fleet update.** Admission keys on the
peer's certificate identity, falling back to **source IP** where no client
certificate is presented. Every certless agent behind one NAT egress therefore
shares **one** bucket: 2 concurrent transfers and a sustained 1 admission per
minute for the entire site, after an initial burst of 20.

| Certless devices behind one egress | Time for a fleet-wide update |
|---|---|
| 20 | minutes (absorbed by the burst) |
| 500 | ~8 hours |
| 5,000 | ~3.5 days |

**What to do.** Run `yuzu_ota_admission_key_mode_total` and look at the
`mode="peer_ip"` share. If it is material:

- **Preferred:** enrol those agents with client certificates. Each then gets its
  own bucket and the problem disappears.
- **Otherwise:** raise `--ota-rate-refill-per-min` and `--ota-max-concurrent-per-peer`
  for the rollout window, and raise `--ota-max-concurrent-total` (default 64) if you
  raise the per-peer values across a large fleet.

Watch `yuzu_ota_download_admission_total{decision="rejected_rate"}` during the
rollout, and see the "Agent OTA pull bounds" runbook in `server-admin.md`.

Also new, and **check this one before you upgrade a large fleet**:
`--grpc-max-threads` (default 8192) now caps the gRPC sync server's thread pool.
Previously nothing did. It is a fleet-size ceiling rather than a tuning dial —
`AgentService` is synchronous and `Subscribe` holds one thread for the life of
each connected agent's command stream, so the value must exceed your
concurrently-connected agent count. Below it, gRPC answers `RESOURCE_EXHAUSTED`
to every RPC on every service sharing the quota, which is a fleet-wide outage
rather than back-pressure. 8192 covers the fleets this release targets; if you
run more than ~5,000 concurrent agents, raise it (`expected_agents x 1.5`)
in the same change as the upgrade.

`--ota-cert-reserve-pct` (default 50) reserves half of `--ota-max-concurrent-total`
for peers admitted on a certificate identity. If your fleet is largely
unenrolled — no client certificates, so admission keys on source IP — the
remaining half is the whole capacity those agents can use, and you may want to
lower the reserve or raise the total for the rollout window.

## ⚠️ Security: rotate `oidc_client_secret` if it was ever set on this install

**Every release up to and including v0.13.0** emitted the OIDC client secret in the clear to three
places, and this upgrade closes all three:

- the **server log**, written verbatim by the startup override pass on **every boot**;
- `GET /api/config`, a route gated only on `Infrastructure:Read`;
- the `config.update` **audit detail** written by `PUT /api/config/:key`, which is durably retained and
  readable by every role seeded `AuditLog:Read` - the seeded `Operator` role among them.

**Breaking for automation:** closing the second path changed a response shape.
`GET /api/config` now reports `"is_set": true|false` for a secret-valued key instead of `value`, so a
client reading `value` for `oidc_client_secret` gets nothing where it previously got the credential.
Full shape and the reason it is not a placeholder:
[`rest-api.md`](rest-api.md#get-apiconfig).

Because the log path fired on every boot, **historical logs** — and anything that ingested them, such
as journald, a Docker log driver, or a SIEM — may still hold the secret in plaintext. Purge or restrict
those as your retention policy allows.

Audit rows written before the upgrade are now redacted when read, so the value stops being disclosed
through that path too. The rows themselves are deliberately left intact: an audit row is compliance
evidence, and rewriting history to conceal a mistake is a worse posture than declining to disclose it.
**So the plaintext remains at rest** in those rows, and a direct database read or a restored backup
still shows it. Do not assume a fixed expiry: `audit_retention_days` defaults to 365, but each prune
pass is capped, and the retention guard deliberately declines a pass after a clock anomaly or a long
outage, so rows can outlive the nominal figure. The secret also remains stored in plaintext
in runtime-config; this fix closes disclosure paths and does not encrypt it at rest (see
`security-hardening.md`, "Current encryption posture").

**Who this affects:** any install where `oidc_client_secret` was ever set through **Settings -> OIDC**
or `PUT /api/config/oidc_client_secret` on an affected release. All three paths above read from
runtime-config, so a secret supplied **only** via `--oidc-client-secret` or `YUZU_OIDC_CLIENT_SECRET`,
and never written through Settings or the API, was not disclosed by *those three paths*.

**That is not the same as "not disclosed".** A secret passed as `--oidc-client-secret` sits in the
process command line, world-readable through `ps` or `/proc/<pid>/cmdline`, and it is typically also in
a systemd unit, a Compose file, or shell history. If you cannot rule those out, rotate anyway.
`YUZU_OIDC_CLIENT_SECRET` is better against other local users — `/proc/<pid>/environ` is owner-only,
unlike `cmdline` — but it is *not* better if the value is written into a Compose file or unit, since
`docker inspect` exposes it to anyone in the `docker` group. Prefer a secrets manager that injects the
environment variable at runtime.

**Before you begin, check you have a local account you can sign in with** — and on
`--auth-mode=sso-only`, that it is the configured break-glass account, MFA-enrolled and armable.
Rotating breaks SSO until Yuzu is re-pointed, and the way back in needs an account that already exists:
break-glass *names* one rather than creating it. On an install with none, the only fallback
[`auth-db-recovery.md`](../ops-runbooks/auth-db-recovery.md) documents is destructive.

**What to do: rotate the client secret at your IdP, and delete the old one.** The upgrade closes the
disclosure paths but **does not change the stored value** — anything that already read it still holds a
working credential, and only the IdP can invalidate it. Most IdPs let you *add* a second client secret
without removing the first; adding one is not a rotation, because the disclosed secret keeps working
until it is deleted.

Deletion does not reach what the secret already bought: access tokens minted with it are signed JWTs
that stay valid until they expire, and IdP sessions can outlast them. Treat revoking those as part of
the same job. Yuzu's own sessions are separate — the IdP cannot reach them — and last at most 8 hours; with
the Postgres substrate they are durable rows and **survive a restart**, so a restart does not end them.
End them per operator via `DELETE /api/v1/sessions?username=<name>` (admin, `UserManagement:Write`;
for an SSO operator the name is `oidc:<iss>#<sub>`). **Neither reaches API
tokens**: one minted under a session that used the disclosed secret survives every step above. List
them with `GET /api/v1/tokens` and revoke with `DELETE /api/v1/tokens/{id}`.

Re-pointing Yuzu at the new secret is a configuration task rather than a remediation one: once
everything above is dealt with, SSO failing until you update it is an outage, not a continuing
disclosure. It is also configuration-specific and easy to get subtly wrong, so it is being written up as
a reviewed runbook rather than summarised here. Until that lands, see
[`authentication.md`](authentication.md) ("OIDC Single Sign-On") for the durable and non-durable ways to
configure OIDC.

## ⚠️ Breaking: a multi-host `--postgres-dsn` now needs `target_session_attrs=read-write`, and `load_balance_hosts` is refused (HA WS-8)

Affects you only if the server's Postgres connection names **more than one host** — `host=n1,n2,n3`,
`postgresql://n1,n2/yuzu`, a `PGHOST`/`PGHOSTADDR` list in the server's environment, or a host list in
the `pg_service.conf` entry a `service=` DSN or `PGSERVICE` names — or sets `load_balance_hosts` (in
the DSN, `PGLOADBALANCEHOSTS` or that service entry). A single host without `load_balance_hosts`,
including a proxy or managed endpoint (RDS, Azure Flexible Server, Cloud SQL, the shipped HAProxy
compose), is unaffected.

Check before upgrading — look for a host list or load balancing in the DSN and the server's environment:

```bash
grep -rnE 'YUZU_POSTGRES_DSN|postgres-dsn|PGHOST|PGHOSTADDR|PGLOADBALANCEHOSTS|PGSERVICE' \
  /etc/yuzu/ /etc/systemd/system/yuzu-server.service* <your compose/env files> 2>/dev/null
```

If that shows `service=` or `PGSERVICE`, also read the named entry in the service file libpq uses
(`PGSERVICEFILE`, else `~/.pg_service.conf` of the server's user, else `pg_service.conf` in
`PGSYSCONFDIR`) for `host`, `hostaddr`, `load_balance_hosts` and `target_session_attrs`.

- **No `target_session_attrs` set:** the server adds `target_session_attrs=read-write` and logs a
  warning at startup (`... using target_session_attrs=read-write ...`). It will no longer connect to a
  standby, which it previously could do silently whenever a standby was listed first. The DSN is
  rebuilt from libpq's own parse — the same settings in keyword form — and checked option by option
  before use. Set the attribute yourself to silence the warning.
- **`read-write` or `primary`:** unchanged.
- **Any other value** (`any`, `read-only`, `standby`, `prefer-standby`, or an unrecognised one): **the
  server refuses to start** with `Invalid --postgres-dsn: ...`. Change it to `read-write` (or remove it)
  before upgrading.
- **`load_balance_hosts` set to anything but `disable`** (in the DSN or `PGLOADBALANCEHOSTS`), with any
  number of hosts: **the server refuses to start**. Remove it (or set `disable`) before upgrading. The
  server writes to one primary, so with read-write the shuffle balances nothing — and `/readyz` holds
  one connection, so it cannot see a host that fails only some of the pool's shuffled connections.
- **A `service=` entry or `PGSERVICE`:** libpq applies the service file only when it connects, so
  the server checks what libpq resolved on its first Postgres connection at startup, and refuses to
  start (`Invalid Postgres connection settings: ...`) if the resolved settings set
  `load_balance_hosts`, or list several hosts without `target_session_attrs=read-write` (or
  `primary`) — it cannot add the attribute to a service file, so set it there yourself. The readiness
  probe repeats the check each time it opens a connection, but it keeps a healthy one open, so a
  later edit that breaks these rules shows on `/readyz` only at its next reconnect — **restart the
  server after editing the service file**.
- **Not checked — set `target_session_attrs=read-write` yourself:** one host *name* that resolves to
  several servers (DNS round-robin, a Kubernetes headless service).

## Behaviour change: `/readyz` now goes red when Postgres is unreachable, and shutdown can hold for a drain grace (HA WS-8, ADR-2002 §12)

`/readyz` gains a gating `pg_reachable` row, fed by a small probe on its own Postgres connection. Before
this change, `/readyz` stayed **200** through a Postgres outage whenever the server had idle pooled
connections or no traffic (the pool's connect breaker only notices a failed *new* connection, and every
store's row only reports whether it opened at startup). A load balancer health-checking `/readyz` kept
sending traffic to a server that could not serve it.

What you may observe after upgrading:

- **`/readyz` answers 503 during a database outage or failover**, with `"failed_stores":["pg_reachable"]`
  and a `"pg"` reason (`unreachable`, `stale`, `read_only`, `not_yet_probed`). During a Postgres failover
  every replica goes red at once, for roughly the failover time. If an orchestrator's **liveness** probe
  points at `/readyz`, move it to `/livez` before upgrading — otherwise a database blip restarts every
  server.
- **One more Postgres connection per server** (the probe). Budget `N_servers × 2` connections beyond the
  pool against `max_connections` (the other extra one is the leader-election connection) — the full
  formula is in `server-admin.md`, "Sizing `max_connections`".
- **The shipped `yuzu-postgres` images now reserve connection slots for the app role** (#4943):
  `reserved_connections = 40` (env `YUZU_PG_RESERVED_CONNECTIONS`) and `GRANT pg_use_reserved_connections`
  to the app role, applied at **first boot only** (PostgreSQL 16 or newer). Three cases:
  - **A fresh install or reinstall** (a new, empty data volume) picks up the new default **silently, with no
    action needed** — but it also reduces headroom for third-party tooling (a backup job, a monitoring agent)
    sized against `max_connections` alone with no margin by up to 40 connections versus a deployment built
    before this release.
  - **An in-place upgrade of an existing database does NOT pick this up** — the new default only applies at
    first boot, and an existing data volume already had its first boot. Without action, a backup job or
    ad-hoc session can still take the slot the `/readyz` probe needs to reconnect, same as before this release.
  - **To apply it to that existing database**, run the `ALTER SYSTEM` (restart) and the `GRANT` by hand as
    "Sizing `max_connections`" above shows.

  **A new boot-time failure mode on the Postgres container itself**, not just the server binary: both
  `yuzu-postgres` images now refuse to start if `YUZU_PG_RESERVED_CONNECTIONS` is set at or past
  `max_connections − superuser_reserved_connections` — that value would leave zero connection slots any
  other client could ever use. Only reachable by explicitly setting the env var too high; the shipped
  default (40) never triggers it. On the single-node image this refusal happens after the role/database/grant
  already exist, so restarting the same container with a corrected value does not retroactively apply
  anything — see the note in "Sizing `max_connections`" above.
- **A new alert, `YuzuServerPostgresUnreachable`**, and three `yuzu_server_pg_reachab*` metrics — see
  `docs/user-manual/metrics.md`.
- **New flag `--shutdown-drain-seconds`** (`YUZU_SHUTDOWN_DRAIN_SECONDS`, default **0**, max 60). On
  `SIGTERM` the server keeps serving for at least that long after `/readyz` turns `503 draining`, so a load
  balancer stops routing to it before the listener closes. The default 0 keeps today's shutdown timing;
  set it for any deployment behind a load balancer, **and raise your orchestrator's stop timeout by the
  same amount** (guidance in `docs/user-manual/server-admin.md`, "Load balancers and shutdown drain"). The
  execution-drain wait it sits alongside is now timed in wall-clock seconds (at most 30 s) rather than
  counted as 30 polls.
- **`/readyz` also goes red on a primary that refuses writes** (`default_transaction_read_only` on — some
  managed Postgres services do this when storage fills), reported as `"pg":"read_only"`.
- **Multi-host `--postgres-dsn` now requires `target_session_attrs=read-write`** — a breaking change
  with its own section above.
- **Docker healthchecks.** The demo and viz-UAT composes healthcheck `/readyz`; that is right for
  readiness, but under Docker Swarm or an auto-heal sidecar an outage longer than the healthcheck's
  retry window marks the container unhealthy and restarts it. Point restart-driving checks at `/livez`.

**What to do:** point liveness probes at `/livez`, readiness at `/readyz`; size `max_connections` by the
formula and apply the reserved-slot grant on an existing database; set `--shutdown-drain-seconds` and the
recommended health-check thresholds if a load balancer fronts the server.

## Behaviour change: legacy `/api/executions*` routes are now management-group confined (#3789)

The legacy pre-v1 `GET /api/executions` (list), `/{id}` (detail), `/{id}/summary`, `/{id}/agents`,
`/{id}/children`, `POST /{id}/rerun`, and `POST /{id}/cancel` routes previously carried NO
management-group confinement at all — a bare `Execution:Read`/`Execute` grant, global or
group-scoped, saw and could act on the entire fleet's executions. They now gate on
`require_fleet_read`, the same admit-then-filter mechanism `GET /api/v1/executions/{id}` already
used.

**Who this affects:** operators holding `Execution:Read`/`Execute` ONLY through a management group
(not a global grant) — these callers are newly ADMITTED to the five GET routes (previously flat
`403`'d outright) but see a narrowed, redacted view. A global grant holder sees no behavior change
on read shape. Everyone sees the following response-shape changes regardless of scope:

- `GET /{id}/summary`, `/{id}/agents`, and `/{id}/children` now return `404` for an unknown
  execution id, instead of a zero-filled/empty `200`.
- `POST /{id}/cancel` now returns `404` for a nonexistent execution id, instead of a false
  `200 {"status":"cancelled"}` (the underlying `UPDATE` always reported success even when it
  matched zero rows).
- A caller holding `Execution:Execute` but **not** `Execution:Read` can no longer rerun or cancel
  an execution — both mutating routes now also require `Read` admission through the fleet gate,
  since `require_fleet_read` is the only place the mutation's target-visibility check happens.
- `GET /api/executions` (list) now caps `limit` at 500 (previously unbounded).
- A gate failure caused by a degraded RBAC/management-group store now returns `503` with
  `retry_after_ms` instead of a flat `403`.
- **`rerun`'s unknown-id response differs by grant scope, deliberately.** A confined caller
  attempting a rerun always gets the uniform `404` above. An UNCONFINED (global-grant) caller
  hitting a genuinely unknown execution id instead keeps the pre-existing
  `400 {"error":"original execution not found"}` from `create_rerun` — unchanged from before
  #3789, and intentionally not unified with the new `404`, to minimize behavior change for
  existing global-grant automation. `cancel` has no equivalent asymmetry: it returns `404` for an
  unknown id under every grant scope.
- An execution whose targeted cohort never fully reports (an agent that went permanently offline
  mid-run, for example) can permanently fail `rerun`/`cancel`'s complete-cohort check for a
  confined caller. The escape hatch is a **global** `Execution:Execute`+`Execution:Read` grant,
  which is never subject to this confinement rule.

**What to do:** if you have automation with a group-scoped (not global) `Execution:Read`/`Execute`
grant, re-verify it still sees the executions it depends on — a confined caller now sees only
executions it dispatched itself or that involve at least one agent it can see, rather than being
denied outright or (previously) seeing everything. If you scripted around the old `/cancel`
false-success or the old zero-filled `/summary` response for an unknown id, update to expect `404`.

**Verify:** `GET /api/executions/{id}` for an execution outside your management-group scope should
return `404`, not the previously-unfiltered full record. `docs/auth-architecture.md`'s "Fourth
migration (#3789)" section has the full design; `docs/user-manual/rest-api.md`'s "Executions"
section has the per-route reference including the `503` shape and the `rerun` escape hatch above.

## Behaviour change: Destructive-class dispatch now requires explicit `agent_ids` on REST and MCP (#3685)

17 `plugin.action` pairs are classified `Destructive` in the command catalogue: `tar.purge_source`,
`tar.rollup`, `filesystem.delete_lines`, `registry.delete_value`, `registry.delete_key`,
`storage.clear`, `content_dist.stage`, `content_dist.execute_staged`, `content_dist.cleanup`,
`content_dist.upload_file`, `tags.clear`, `script_exec.exec`, `script_exec.powershell`,
`script_exec.bash`, `http_client.download`, `certificates.delete`, and `quarantine.quarantine`
(19 as of this writing — `power_health.set_power_plan` and `printing.clear_queue` have since joined
them, under the same rule).
Dispatching any of them without explicit, non-empty `agent_ids` — an omitted/empty target, or a
`scope` (including `"__all__"`, even alongside `agent_ids`) — is now refused with `400`
(`"destructive action requires explicit in-scope agent_ids; broadcast and scope fan-out are
refused"`) on REST `POST /api/command`, and `-32602` with the same message on MCP
`execute_instruction` (refused before an approval ticket is minted or consumed, at both the
supervised-tier pre-mint gate and the operator-tier handler).

**MCP `execute_instruction` had no Destructive-targeting gate at all before this release** — a
scope-targeted or broadcast call to one of the 17 rows above dispatched normally and succeeded.

**REST `/api/command`'s outcome for these 17 rows is unchanged** — the prior guard already denied
a scope-targeted or broadcast dispatch to any of them, both before and after this release. What
changed on REST is the guard's shape, not its outcome: the prior code was an `if` that collapsed
"classified and not Destructive" and "failed to classify at all" (a classify-miss) into the same
skipped branch, relying on a classify-miss being denied unconditionally further downstream
(`build_classified_command`) rather than proving that locally. This release replaces it with an
exhaustive switch with no default arm, so a future change to the verdict enum forces a
compile-time decision here too, instead of silently falling through to a guard shape that was
correct only because of a downstream backstop.

**Who this affects:** two surfaces change outcome in this release. **MCP `execute_instruction`**,
for any operator or automation dispatching one of the 17 rows above with `scope` or an
omitted/empty target. And the **dashboard execute surface** (`POST /api/dashboard/execute`), which
gains the gate for the first time here — including the case most likely to bite, an **omitted**
scope: that surface treated "no target named" as the whole fleet, so console automation that
posted neither `agent_ids` nor `scope` for one of these rows previously dispatched fleet-wide and
is now refused. A REST `/api/command` caller was already refused before this release and sees no
behavior change. Dispatches to a row NOT on this list are unaffected on all three surfaces.

**A second dashboard change, distinct from the targeting gate:** an explicitly-targeted Destructive
dispatch from the console is now confined to the agents visible to the calling operator, matching
REST. With RBAC off this is a no-op — every enrolled agent belongs to the auto-created root "All
Devices" group, so the visible set is the whole fleet. It bites only with **RBAC enforcement on**
where an operator holds `Execution:Execute` as a global grant rather than through a
management-group role: that operator has no management-group rows to be visible through, so the
confined list is empty and the dispatch is refused with `no reachable in-scope agent` (audited
`reason=scope_violation`). The fix is to grant the operator a management-group role covering the
agents they administer. Note the message names in-scope reachability, not connectivity — an agent
shown as online in the console can still produce it.

**What to do — the field to send differs by surface, so do not apply one remediation to both:**

- **MCP `execute_instruction`** (and REST `/api/command`): send an explicit, non-empty
  `agent_ids` array.
- **Dashboard `POST /api/dashboard/execute`**: this endpoint has **no `agent_ids` field** and
  ignores one if sent. It takes a single `scope` form field, and one explicit agent is expressed
  as `scope=<agent-id>` (a management group is `scope=group:<id>`, the fleet is `scope=__all__` —
  the latter two are what the gate now refuses for Destructive rows). Console automation must
  therefore send `scope=<agent-id>`. The browser UI already does this and needs no change.

In both cases, if RBAC is enforced, also confirm the calling operator's management-group roles
cover the agents named — see the confinement note above.
`POST /api/instructions/{id}/execute` and MCP `execute_bundle` do not yet enforce the gate — a
tracked follow-up, not a gap this release closes.

**Verify:** re-run the affected dispatch with an explicit single target — `agent_ids` on
MCP/REST, `scope=<agent-id>` on the dashboard — and confirm it succeeds as before; a group-scope,
broadcast, or untargeted call to one of the 17 rows should now return the refusal above rather
than dispatching. To confirm the gate is exercising in your environment:

```promql
yuzu_server_dispatch_target_rejected_total{route=~"command|mcp|dashboard",reason="destructive_untargeted"}
```

Note the regex matcher (`=~`): a label matcher cannot take an alternation of quoted strings. The visible-agent confinement refusal is deliberately **not** on that counter —
look for the `command.dispatch|denied` audit row carrying `reason=scope_violation` instead.

## Behaviour change: SAML login gains a new availability coupling to `rbac_store` (#1832)

SAML SSO now reaches parity with OIDC's group-to-role RBAC reconciliation (see
[`authentication.md`](authentication.md) "SAML Fine-Grained RBAC"). This introduces a
coupling that did not exist before: on a deployment that already has **RBAC enabled**
**and** `--saml-group-attribute` configured, a SAML login now depends on `rbac_store`
being reachable — a transient reconcile-store error denies the login outright
(fail-closed), rather than granting a session under stale or unreconciled roles.
Previously, a `--saml-group-attribute`-configured deployment's SAML logins did not
touch the RBAC store at all (only the coarse `--saml-admin-group` admin/user mapping
ran), so this is a genuinely new dependency for that combination of flags, not a
tightening of an existing one.

**What to do:** if you run SAML with both RBAC enabled and `--saml-group-attribute`
set, ensure `rbac_store` (PostgreSQL) health and availability are covered by whatever
you already monitor for RBAC-gated REST/MCP calls — a `rbac_store` outage now also
takes down SAML login for that deployment, not just RBAC-gated reads. Deployments that
leave `--saml-group-attribute` unset, or that run with RBAC disabled, are unaffected —
this section is a no-op for them.

**Also note:** the `--saml-group-attribute` group-value cap (`saml::kMaxGroupValues`)
is raised from 64 to 200 in this release, to align with
`RbacStore::kMaxIdpGroupsPerLogin`. A SAML assertion carrying 65–200 group values,
which previously had its excess values silently truncated (and the login still
succeeded), now has all of them considered. An assertion carrying more than 200 group
values, which previously also truncated-and-logged-in, now instead **denies the
login** (mirrors OIDC's `group_count_exceeded` behaviour) — see "SAML Fine-Grained
RBAC" in `authentication.md` for the full detail, including the practical httplib
form-body-size caveat on how large an assertion can realistically reach `/saml/acs`.

## Behaviour change: InstructionStore moves to PostgreSQL — deleted content no longer resurrects (ADR-0058)

`InstructionStore` (InstructionDefinitions and InstructionSets — the operator- and
build-time-shipped instruction/question catalog) moves from per-replica SQLite to the shared
PostgreSQL substrate (ADR-0006/0007), like every other migrated store. **No legacy-SQLite
backfill** (ADR-0009's fresh-start-by-default class, following `ResponseStore`'s precedent): no
production fleet has ever run a pre-Postgres build of any Yuzu store, so the pre-migration
`instructions.db` is never read. On upgrade, the bundled catalog reseeds fresh on first boot the
same way it always does, and any operator-authored content must be re-created via the normal
API (`POST /api/instructions`, `POST /api/instruction-sets`) — there is no automatic carry-over.

**Breaking, deliberate: an operator-deleted bundled definition/set no longer reappears.**
Since 0.12.x (see that row above), deleting a build-time-shipped definition and rebooting made
it silently reappear — the old per-replica SQLite reseed logic couldn't distinguish "never
seeded" from "deliberately deleted", so `enabled: false` was the documented workaround for
permanent suppression. **That workaround is no longer necessary but still works.** Post-upgrade,
a deleted bundled id stays deleted — across every reboot, every replica, and every future
release — via a tombstone the reseed loop consults. **Recovery path:** the tombstone only
gates the build-time-trusted reseed path; an operator can still freely bring the id back at any
time via a normal `POST /api/instructions` create or `POST /api/instructions/import`.

**A side effect worth knowing:** delete-and-reboot was also, incidentally, the only existing
way to force an existing bundled definition to pick up *newer* bundled content shipped in a
later release (delete it, then the next boot's reseed re-inserts the current version). That
side channel is now closed along with the resurrection bug it depended on — an existing bundled
row, edited or not, never automatically picks up newer shipped content. There is currently no
other refresh mechanism; tracked in [#2555](https://github.com/Tr3kkR/Yuzu/issues/2555).

**REST contract change** on the direct `/api/instructions*` / `/api/instruction-sets*` routes:
`DELETE` on a missing id now returns `404` (was `200 {"deleted": false}`); `create`/`update`/
`import`/`create-set` now return `503` on a genuine database failure instead of a misleading
`400`. See [`rest-api.md`](rest-api.md#instructions) for the full per-route response-code
reference. Any automation that specifically parsed the old `200 {"deleted": false}` shape or
treated every non-2xx response as a validation error should be updated.

No operator action is required to upgrade; the reseed loop runs automatically at boot. See
`docs/adr/0058-instruction-store-postgres-migration.md` for the full design record.

**Caveat (rollback direction):** the above covers forward migration only. `instructions.db`
still exists after the upgrade (it keeps backing the still-SQLite
`ExecutionTracker`/`ApprovalManager`/`ScheduleEngine` siblings), but this binary never writes
InstructionDefinition/InstructionSet rows to it. If you roll the server *binary* back to a
pre-migration release, the outcome depends on your deployment's history and is never an empty
catalog either way — the pre-migration binary's own boot sequence unconditionally
`CREATE TABLE IF NOT EXISTS`-es the catalog tables and runs its own every-boot bundled-content
reseed loop, the same way this store always has:
- **A deployment that upgraded from a pre-migration install** still has its old
  `instructions.db` catalog tables, untouched by the new binary. The rolled-back binary reads
  them and serves that pre-cutover snapshot — including re-resurrecting any bundled definition
  or set an operator deliberately deleted in Postgres after cutover, since the old binary has
  no concept of the tombstone table.
- **A deployment that was Postgres-first from its first boot** has no catalog tables in
  `instructions.db` yet. The rolled-back binary creates them fresh and reseeds that old
  release's full bundled catalog — a stale but non-empty catalog, not an empty one.
- **Either way, anything created or edited via the API while running the new (Postgres)
  binary is invisible during the rollback** — it lives only in Postgres, which the old binary
  never reads — and, because there is no backfill, is not recovered automatically when you
  roll forward again either; content authored while rolled back must be re-entered.

## Behaviour change: token-rotation confirm now requires proof of possession (#3015)

`confirm` on a rotation — REST `POST /api/v1/tokens/{id}/confirm` and `POST /api/v1/engine-principals/{id}/credentials/confirm`, plus the MCP twins `confirm_api_token_rotation`/`confirm_engine_rotation` — previously admitted on caller identity plus the successor's `token_id` alone. A caller who recovered an unknown successor's `token_id` out-of-band (a support ticket, a log line) could confirm — and thereby revoke the predecessor for — a rotation whose secret they never actually received. All four confirm surfaces now additionally require the raw successor secret itself in the request body/args, verified with a constant-time hash comparison against the successor's stored hash, checked LAST — strictly after ownership, pair-state, the `token_id` pin, tier, scope, and the initiator binding have all already passed — before the predecessor is touched.

**Who this affects:** any caller (human or automation) confirming a rotation with only the `token_id`, and any caller confirming with the wrong secret.

- **REST:** a confirm body carrying no `secret` field (or an empty one) now gets `400` instead of succeeding; a wrong `secret` gets `403`.
- **MCP:** `confirm_api_token_rotation`/`confirm_engine_rotation` called without a `secret` arg now get `kInvalidParams`; a wrong one gets `kPermissionDenied`.

Correctly-implemented automation already holds the secret — it's the same raw value the `rotate` response returns exactly once (REST `data.token`) — so a caller that installs the successor from that response and passes it straight through to `confirm` sees no change in behavior.

**What to do if you lose the rotate response before confirming:** you can no longer confirm — there's no way to manufacture the secret from the `token_id` alone. Two recovery paths, and neither is new — this change makes the mechanism enforce guidance already documented in [`authentication.md`](authentication.md#rotating-a-token) "Rotating a Token" (don't look the successor up and confirm blind):

1. **Wait for the automatic overlap-window sweep.** Proof of possession gates this immediate, explicit `confirm` call only — the 60-second background sweep is unaffected by this change and still auto-revokes the predecessor on its own schedule with no secret required, provided the successor secret was actually installed and presented (used) at least once.
2. **Revoke the unknown successor and start a new rotation.** This keeps the predecessor working immediately, at the cost of restarting the rotation.

See [`authentication.md`](authentication.md#rotating-a-token) and [`engine-principals.md`](engine-principals.md) for the full detail, and [`rest-api.md`](rest-api.md) for the exact REST error bodies.

## Behaviour change: MCP approval-store permanent failures now say don't retry (#2786)

An MCP approval-ticket recall that hits a store fault has always returned `-32603` with a `retry_after_ms` hint. Previously that hint was `5000` (retry after 5 seconds) for every store fault except a never-opened store, including one that was open but failing in a way no amount of retrying clears — SQLite corruption, not-a-database, a read-only filesystem, or a full disk. Those four cases now correctly get `retry_after_ms: null` (the same "escalate to an operator" response a never-opened store gets) instead of the transient retry hint.

**What to do:** if you have automation that blindly retries on `-32603` without checking `retry_after_ms`, it now stops retrying sooner in this specific case — which is the correct behavior (the old retries were futile). If your automation already honors `retry_after_ms` per [invariant A5](../agentic-first-principle.md), no change is needed. See [`mcp.md`](mcp.md) "`-32603`: Approval store unavailable" for the full response-body reference.

## Behaviour change: four MCP tool input schemas got stricter (#2444)

`revoke_certificate.serial_hex`, `confirm_engine_rotation.token_id`, `quarantine_device.reason`/`whitelist`, and the eight *approval-gated* engine-principal tools' `principal_id` (`create`/`revoke_engine_principal`, `mint`/`rotate_engine_credential`, `transfer_engine_principal_owner`, `assign`/`unassign_engine_role`) now carry `pattern`/`maxLength` bounds mirroring their handlers' own checks (previously enforced only at the handler, after an approval ticket was already consumed). `get_engine_principal` and `list_engine_roles` also gained the same `principal_id` pattern, but per this codebase's standing rule that input-schema validation runs only on the approval-gated path (`mcp-server.md`'s "Pre-approval input-schema validation"), those two are Read-tier and never approval-gated — the pattern is advertised metadata on `tools/list` only, not server-enforced; a malformed `principal_id` still reaches the handler and is rejected there exactly as before.

**Who this affects:** any operator or automation with an outstanding (pending or
approved-but-unconsumed) approval ticket for one of these ten tools —
`revoke_certificate`, `confirm_engine_rotation`, `quarantine_device`,
`create_engine_principal`, `revoke_engine_principal`, `mint_engine_credential`,
`rotate_engine_credential`, `transfer_engine_principal_owner`,
`assign_engine_role`, `unassign_engine_role` — whose arguments don't match the
new bound: `serial_hex` must be `^[0-9A-Fa-f]{1,64}$`; `token_id` must be
`^[0-9a-f]{24}$`; `quarantine_device.reason`/`whitelist` must be ≤1024/≤512
bytes (whitelist additionally charset-restricted); `principal_id` must match
`^engine:[a-z0-9._-]+$` (or the bare-slug form on `assign`/`unassign_engine_role`).
Full patterns: `mcp-server.md`'s "Pre-approval input-schema validation" section.

**What to do:** such a ticket becomes unrecallable fail-closed once the new
server is running — the recall fails pre-consume just like any other
schema-invalid call, and the ticket is never burned, but it also can't be
redeemed as originally minted. It stays valid until its normal 7-day expiry
(pending or approved-unconsumed), then ages out and must be re-requested. To
check exposure before upgrading, list your outstanding tickets for these ten
tools (`list_pending_approvals` MCP tool or `GET /api/v1/approvals`) and
compare each one's arguments against the patterns above; no action is needed
for a ticket that already matches, or if you have none outstanding.

**Verify:** re-request any ticket the check above flagged, confirm the new
recall succeeds under the same tier, and confirm a deliberately malformed
value (e.g. a non-hex `serial_hex`) is now rejected at mint time — `-32602`,
no approval created — rather than being accepted and only failing later at
the handler.

## Behaviour change: `discover_instructions`/`GET /api/v1/discover/instructions` null out a non-object stored `parameter_schema` (#2986)

Both surfaces share one builder (`build_instructions_catalog`) that parses each `InstructionDefinition`'s stored `parameter_schema` text. It previously forwarded any value that parsed as JSON, even a non-object (an array, string, number, or boolean). It now forwards it only when the parsed value is itself a JSON object — a non-object value is reported as `null` instead, matching `GET /api/v1/discover/plugins`' existing behavior for the same field.

**Who this affects:** an operator or integration that authored an `InstructionDefinition` with a non-object `parameter_schema`, written before the write-time schema check existed, or by a non-standard write (the store now refuses a non-object `parameter_schema`, and `POST /api/instructions/import` is the only REST route that can supply one). No shipped content sets `parameter_schema` to anything but an object or leaves it unset (defaults to `{}`), so this affects only a deliberately or accidentally malformed definition.

**What to do:** if you have such a definition and relied on the old raw-forwarding behavior, re-author `parameter_schema` as a JSON Schema object (see [Replacing a stored parameter schema](instructions.md#replacing-a-stored-parameter-schema)). No action is required otherwise.

## Behaviour change: webhook and offload-target deliveries, and enrollment/execution-failure notifications, now actually fire (#3261)

A boot-ordering bug wired `NotificationStore`/`WebhookStore`/`OffloadTargetStore` into
the agent-service RPC path (`Register`, `Subscribe`, `process_gateway_response`) before
those three stores were constructed, so the wiring silently never took effect. Dashboard
notifications for agent enrollment and execution failures, and configured webhook/offload
deliveries for `agent.registered` and `execution.completed` events, have been dead for
the life of the process **since the stores were introduced** — for `NotificationStore`/
`WebhookStore`, every tagged release from v0.10.0 through v0.13.0 (roughly four months);
`OffloadTargetStore` didn't exist until v0.12.0, so its affected window is v0.12.0 through
v0.13.0 (roughly three months). Every use site double-guards `ptr && ptr->is_open()` with a
silent skip, so nothing logged or alerted; the bug produced zero signal. They now fire on
every boot.

**What to do:** if you configured a webhook (`POST /api/webhooks`) since v0.10.0, or an
offload target (`POST /api/v1/offload-targets`) since v0.12.0, expecting live traffic and
saw none, that integration has been silently non-functional the entire time, not merely quiet
— there is no queued backlog to replay, because the events were never generated in the
first place. If you use one of these integrations as part of your own monitoring or
compliance evidence chain (a SIEM feed, an alerting pipeline), treat the gap as a
documented monitoring-coverage lapse for that period, not just a product bug, when
recording it in your own change or incident log. After upgrading, confirm your receiving
endpoint still exists and can handle real traffic before you rely on it — deliveries
start immediately, with no flag or opt-in involved. If your webhook fires to Slack or a
similar noisy channel for enrollment alerts, note that `agent.registered` fires on every
gRPC reconnect, not only first enrollment (this is unchanged, documented behaviour — see
"Webhooks" / "Offload Targets" in [`rest-api.md`](rest-api.md) — but was invisible
until now); the "Agent Enrolled" **dashboard notification** specifically does not repeat
on reconnect, so a server restart with N connected agents does not flood that feed.

## Behaviour change: `mcp.bridge.*` audit rows can now carry `result=failure` (#2487 / #2506)

Audit rows for the MCP progress bridge (`mcp.bridge.done_reap`, `session_dead`, `arming_reaped`, `pin_acked`, `forced_expire`) were previously stamped `result=success` unconditionally, regardless of what actually happened. They now report the real outcome: `result=failure` when a background teardown could not release one of the resources it owns, or when the terminal-frame publish ladder poisoned the session, threw, or was never reached. The `detail` field names which, and no longer asserts a delivery or a poisoning that did not occur.

**What to do:** if you have a SIEM rule, dashboard or evidence query that treats `result` on this verb family as a constant `success` - for example "alert if any `mcp.bridge.*` row is not `success`" - update it before upgrading, or it will fire on legitimate rows. Note also that `failure` here is *self-audited*: a rule that surfaces failure branches by filtering on `denied` will not see these. Filter on `result != "success"` where you need both. `mcp.bridge.cancel` is unaffected and remains `success`.

These rows are background-actor events (`principal=system`), not operator actions, and a `failure` row does **not** mean a client lost a result - executions stay durably fetchable by `execution_id`. See [`audit-log.md`](audit-log.md) for the verb family and [`../ops-runbooks/mcp-bridge-teardown-recovery.md`](../ops-runbooks/mcp-bridge-teardown-recovery.md) for what to do when the paired alert fires.

## Behaviour change: MCP unknown-tool calls now audit `result=denied`, not `failure` (#2445)

An MCP `tools/call` request naming a tool that doesn't exist has always returned `-32601` (`kMethodNotFound`) with the same error message. The audit row for that rejection previously carried `result=failure` - the token this codebase reserves for server-side faults - while every sibling denial on the surface (tier, read-only, schema, input-bounds, per-submitter-cap) uses `result=denied`. It now audits `result=denied` too, matching those siblings. Nothing about the JSON-RPC response changed.

**What to do:** if you have a SIEM rule, dashboard or evidence query that classifies `mcp.<tool_name>` rows by filtering on `result=failure` to catch unknown-tool probes, re-point it at `result=denied` before upgrading, or it will stop matching. A rule that already filters on `result != "success"` sees both and needs no change. Note `result=failure` was never a clean isolator for unknown-tool probes specifically - it is also emitted for genuine server-side faults on *known* tools (store degraded, dispatch exception, etc.) and for several other client-caused-but-mislabeled rejections on the same surface (still open, tracked in #3176), so a rule that wants unknown-tool rows specifically should filter on `detail="unknown tool"`, which this change does not touch. See [`audit-log.md`](audit-log.md) "Result vocabulary" for the surface's current token usage.

## Behaviour change: a failed MCP progress-bridge teardown is now retried instead of being permanently retained (#2513)

A `mcp.bridge.*` teardown step (unsubscribe, releasing the streamed admission charge, or erasing the correlation record) that failed used to strand the record - and the bus channel, replay buffer, and per-session admission slot it held - for the rest of the process's life. It now gets up to `Config::teardown_retry_max` retries beyond the first attempt (4 total attempts by default), one per later sweep tick, before falling back to the old permanent-retention behavior. New `yuzu_mcp_bridge_teardown_retry_total{outcome="recovered"|"exhausted"}` metric and `mcp.bridge.teardown_retry` audit action evidence which happened; see [`audit-log.md`](audit-log.md) and [`../ops-runbooks/mcp-bridge-teardown-recovery.md`](../ops-runbooks/mcp-bridge-teardown-recovery.md).

**What to do:** the shipped `YuzuMcpBridgeTeardownIncomplete` alert changed from a raw counter test (fires and never clears, since the underlying series is monotonic) to a windowed `increase(...[15m]) > 0` test, because most of its movement now self-heals via retry within a few sweep ticks. If you copied the old rule into your own alerting config instead of re-importing `docs/prometheus/yuzu-alerts.yml`, update it the same way or it will stay permanently firing on transient, already-recovered blips. The new `YuzuMcpBridgeTeardownRetryExhausted` alert is now the actual permanent-retention signal - add it if you track these alerts individually rather than loading the bundled rules file wholesale.

If you have dashboard or SIEM logic reading the pre-existing `yuzu_mcp_bridge_teardown_incomplete_total` counter directly rather than through the bundled alert - it is unchanged in name and label shape, but its increment semantics changed: previously one increment per stranded record (ever), now up to `Config::teardown_retry_max` + 1 increments for the SAME record (once per failed step, per attempt) before it either recovers or exhausts. Arithmetic that read the counter as "count of stranded records" will now overcount under retry; read `yuzu_mcp_bridge_teardown_retry_total{outcome="exhausted"}` for that instead. `Config::teardown_retry_max` is a code-constant default, not an operator-configurable flag or env var - there is nothing to tune here.

## Behaviour change: agent command replay protection is now durable, and a redelivered command replays its real result (HA WS-0, ADR-2002)

The agent's command deduplication moved from an in-memory set (cleared on every reconnect) to a durable SQLite store (`command_dedup.db` in the agent data directory). Two consequences an operator or automation may observe:

**Breaking for automation/SIEM.** A redelivered/duplicate command no longer receives a `REJECTED` response with the fixed reason `"command replay rejected: duplicate command_id"`. That string **is retired.** A duplicate now either replays the command's **original terminal frame** (its real `SUCCESS`/`FAILURE`/`REJECTED` status, exit code, and structured error — the terminal frame carries the outcome, not the streamed stdout, which is not re-sent) or, while the first attempt is still running, returns a non-terminal `RUNNING` frame with output `"duplicate command still in flight"`. Any detection rule, dashboard, or evidence query that matched the old rejection string on a redelivered command will silently stop matching — re-point it before upgrading (there is no longer a single "this was a replay" signal on the wire; the server correlates by `command_id`).

**What to do:** update or remove any rule keyed on `"command replay rejected: duplicate command_id"`. If you tracked replays for security evidence, note the agent now emits `yuzu.dedup_*` heartbeat tags (`dedup_degraded` for an unopenable store; `dedup_claim_errors`/`dedup_record_errors`/`dedup_release_errors` for post-open write failures; `dedup_replays`) instead; fleet-wide `yuzu_fleet_*` aggregation + an alert land with the HA observability workstream (WS-11).

**New on-disk artifact.** `command_dedup.db` (plus `-wal`/`-shm`) appears in the agent's `--data-dir`, bounded to the most recent commands. It is a regenerable safety net, **not** a backup target. **Upgrade is fresh-start** — no migration from the old in-memory scheme (there was no persistent state to carry); worst case on upgrade is that one already-delivered command could re-execute if redelivered during the restart, exactly as it could before this change. Downgrade is safe: an older agent simply ignores the file.

**Degraded mode is fail-open.** If the store cannot be opened or written (e.g. a full disk), the agent keeps executing commands **undeduplicated** rather than refusing them, and surfaces the condition on the heartbeat: `yuzu.dedup_degraded=1` for a store that never **opened**, and the `dedup_claim_errors`/`dedup_record_errors`/`dedup_release_errors` counters for **post-open** write failures. A per-destructive-instruction-class fail-closed option is planned but not in this release.

## Behaviour change: an MCP maintenance failure degrades instead of aborting the server (#2487)

A transient failure in the MCP progress-bridge sweep or the MCP session collector, which runs on the server's maintenance thread, previously escaped that thread and terminated the whole process. It is now contained: the tick is skipped and retried on the next cycle.

**What to do:** be aware this is a genuine trade, not a pure win. The old failure was self-announcing - the process died, your supervisor restarted it, and uptime monitoring saw it. The new one is silent unless you are scraping metrics: a sustained failure means bridge teardown or session collection stops running, live MCP progress can degrade for the remaining life of the process, and `/readyz` will continue to report healthy throughout (MCP session state deliberately does not gate readiness). If you run Prometheus, scrape `yuzu_mcp_bridge_teardown_incomplete_total`, `yuzu_mcp_maintenance_tick_failures_total` and `yuzu_mcp_bridge_records_active`, and load the bundled rules in `docs/prometheus/yuzu-alerts.yml` - they are not applied automatically. If you do not, you will not see this condition at all.

Note this narrows the crash surface rather than closing it: other work on the same maintenance thread remains unguarded, so a sufficiently severe resource exhaustion can still terminate the process from a different call site.

## Behaviour change: `yuzu-agent` no longer restart-loops forever (ADR-0021 rung 7.7a)

The `yuzu-agent` systemd unit now sets `StartLimitIntervalSec=300` + `StartLimitBurst=5` in its `[Unit]` section. Previously the unit was `Restart=always` with no start limit, so an agent that could not stay up restarted every 10 seconds indefinitely. With this change, if the agent exits 5 times within 300 seconds systemd stops retrying and the unit enters `failed`.

This matters because the agent's Guardian engine can now `hard_exit()` when an I/O worker is wedged past a grace period (a permanently wedged watched target, e.g. a dead NFS mount or a hung service query); without the start limit that would be a silent 10-second crash loop.

**What to do:** if you alert on systemd unit state, add `yuzu-agent` entering `failed` to your alerts - it means the agent gave up after a crash loop and the device is now dark, which the old restart-forever behaviour hid. Recover with `systemctl reset-failed yuzu-agent` once the underlying cause (e.g. the wedged mount) is resolved, then `systemctl start yuzu-agent`. The Guardian spark detection path this rung wires is dormant (`--spark-disable` unchanged, legacy detection unaffected), so there is no detection-behaviour change to account for. See also [`server-admin.md`](server-admin.md) "Stopping a wedged agent".

## Behaviour change: a Guardian rule that fails to arm no longer crashes the agent (ADR-0021 rung 7.7b PR-1a)

Independent of the dormant spark path above, the Guardian engine's `apply_rules` (which runs on the **live legacy detection path** regardless of `--spark-disable`) now firewalls a per-rule reconcile failure. Previously, if arming a rule threw - e.g. a `std::thread` creation failure under resource exhaustion, or a `bad_alloc` - the exception escaped onto the agent's dispatch thread and aborted the whole daemon. It now degrades: the failure is caught and counted, the rule stays persisted, and the agent keeps running. The `full_sync` teardown and the dispatch boundary carry the same firewall.

One behaviour to be aware of: when a rule fails to arm, the agent **holds its policy generation** (does not report "caught up") so the server's heartbeat reconcile keeps re-pushing and retrying - a transient resource failure self-heals within a reconcile cycle. A rule that fails **persistently** (rare - it requires a durable resource condition, not bad rule content) keeps the agent behind-generation and drives a re-push each reconcile interval; this is visible in the server's `guaranteed_state.reconcile` audit rows for that agent. No operator action is required.

## Behaviour change: Guardian event-drop metric narrows to genuine collisions (ADR-0021 rung 7.7b PR-Sv)

Guardian event ingest now distinguishes an idempotent **redelivery** (a matching-fields `event_id` PK conflict — the durable agent lifecycle journal's expected crash-durable, duplicate-tolerant, bounded-retry redelivery, not a guarantee of eventual delivery - an un-acked record that ages out of the 7-day retention window is a rare, counted loss, not silent) from a genuine **collision** (a mismatched-payload conflict — a forged-id pre-claim or an `event_seq_` reset carrying a different event). The eviction-loss counter (`yuzu.guardian_journal_evicted_no_send_evidence`) is in-memory only and resets on agent restart, and today has no dashboard, REST, or MCP surface at all, per-agent or fleet-wide - see [Reconnect replay traffic](guaranteed-state.md#reconnect-replay-traffic-durable-lifecycle-journal) for the full picture (tracked under #2298). **A high redelivery count after an agent outage or reconnect storm is expected and is NOT a loss signal** - genuine loss shows up only as a mismatched collision (`..._events_dropped_total`) or the rare journal-eviction case above. Three operator-visible consequences:

- **`yuzu_server_guardian_events_dropped_total` narrows.** It now counts only mismatched collisions; benign redeliveries move to the new `yuzu_server_guardian_events_redelivered_total`. **If you deployed the bundled `YuzuGuardianEventsDropped` rule from `docs/prometheus/yuzu-alerts.yml`** (a copy, not something the server auto-upgrades) **with your own or a wider threshold tuned to reconnect churn, re-apply the updated rule (now `> 5/1h`)** — otherwise your old threshold's baseline drops post-upgrade and the alert goes **silently dead**, not loud, on a CC7.3 signal.
- **A metric series steps down, and a new one appears.** Any Grafana panel/PromQL against `..._events_dropped_total` shows a step-change *drop* at upgrade with no incident — **expected, not data loss**; watch total PK-conflict volume via the new `..._events_redelivered_total` series. A third new series, `..._events_ingest_errors_total` (with a bundled `YuzuGuardianIngestErrors` alert), counts operational ingest faults so a persistent fault can't silently hide collisions.
- **DEX de-duplication on reconnect.** Before this change, a redelivered event re-ran the DEX blast-radius + alert observers on every agent reconnect. If you saw duplicate/false blast-radius sightings or duplicate routed alerts during reconnect storms, those stop now — an intentional fix, not a regression.

**Verify:** post-upgrade, confirm the new series are present and re-tune any custom copy of the drop alert:

```promql
yuzu_server_guardian_events_redelivered_total   # should appear and climb on reconnects
yuzu_server_guardian_events_ingest_errors_total # should stay at 0 in a healthy fleet
```

No config or data migration is required.

## Behaviour change: a degraded file-change rule now reports itself unhealthy instead of staying silently green (#4748)

A `file-change` Guardian rule watches its target's parent directory to detect the target being renamed or moved. If that watch's own teardown repeatedly fails to confirm (normally only a wedged filesystem driver, or sustained packet loss on a network share), rename detection for that rule permanently disables until the rule is re-armed. Previously the only signal was a single agent log line — the rule kept reporting `guard.compliant` (the device page's compliance census showed it green) for as long as the agent ran, even though it could no longer detect a rename of its watched directory.

After this upgrade, a rule that reaches this state reports itself `errored` on the device page (the same red state as an unresolved drift) instead, with an operator-facing detail explaining the cause and how to recover, and re-asserts every 5 minutes for as long as it stays disabled. The rule's own file presence/content detection is unaffected either way — only rename detection is lost, and only its *reporting* changes here.

**This is not a retroactive flip.** The disabled state is in-memory only (never persisted), so it resets on the very restart that ships this fix — no rule that was showing compliant before upgrading suddenly shows errored at upgrade time. What changes is *future* behavior: if a rule reaches this degraded state after upgrading (e.g. from another bout of network-share packet loss), it now shows red where a pre-upgrade agent would have stayed silently green. If you see a previously-quiet `file-change` rule turn red after upgrading, that is very likely this fix correctly surfacing a pre-existing condition on your network share, not a new regression — see [the degraded-mode section](guaranteed-state.md#file-guards--detect-a-file-changed-or-deleted-in-realtime) for the recovery steps (re-push the rule's policy, re-deploy its Baseline, or restart the agent).

No config or data migration is required.

## Behaviour change: dashboard YAML Save is schema-aware and stricter (#1993)

`POST /api/instructions/yaml` (the New Definition panel's Save endpoint) and
`POST /api/instructions/validate-yaml` now share one schema-aware parser that
accepts the canonical nested InstructionDefinition schema (`metadata.id`,
`spec.execution.plugin/action` — the documented format every shipped
definition uses), which the old substring scanner rejected. In exchange, the
endpoint is stricter about malformed input:

**Who this affects:** automation POSTing YAML to `/api/instructions/yaml`
that (a) omits `apiVersion:`/`kind:` lines, (b) relied on a stray `name:`
substring anywhere in the document being picked up as the definition name,
(c) re-creates a definition whose `metadata.id` already exists (now **409**
with a denied audit row instead of a silent second copy under a generated
id), (d) supplies an explicit id outside `[A-Za-z0-9._-]{1,128}`, or
(e) pastes multi-document (`---`-separated) files (now rejected; save one
definition at a time). Interactive panel users are unaffected — the
structured form's output stays accepted.

**Verify:** re-run your automation against a test server; failures surface as
specific per-field messages (e.g. `Missing metadata.id (or metadata.name)
field`), and successful saves now emit `instruction.create` /
`instruction.update` audit rows.

## ⚠️ Reserved on-behalf-of headers rejected + `principal_class` metric label (ADR-1005 Phase 1)

Two operator-visible changes ship together:

**1. Reserved headers now 403.** Five header names are reserved and rejected
on every HTTP endpoint before authentication (`On-Behalf-Of`,
`X-On-Behalf-Of`, `X-Yuzu-On-Behalf-Of`, `X-Yuzu-Delegated-Operator`,
`X-Yuzu-Delegation-Artifact`, case-insensitive; the equivalent gRPC metadata
keys cause the call to be cancelled). Nothing previously consumed these
headers, so a correctly-built integration is unaffected — but **pre-flight
check any proxy, service mesh, or SSO gateway in front of Yuzu**: some
API-gateway products stamp an on-behalf-of/OBO convention header on every
upstream request (the name is Microsoft's Entra OBO term), which would 403
**all** REST/MCP/dashboard traffic after upgrade. Health probes (`/livez`,
`/readyz`, `/health`, `/api/health`) are exempt, so the pod stays in rotation
— a green probe with a 100% 403 rate is the signature (see
`docs/operations/troubleshooting.md`). Rejections are visible in
`yuzu_onbehalf_rejected_total` and throttled `[ADR-1005]` warn lines.

**2. `yuzu_http_requests_total` gains a `principal_class` label**
(`human`/`agent`/`none`; `engine` reserved). This is a Prometheus
series-identity change on a long-shipped metric: old `{method,status}` series
freeze at upgrade and new `{method,status,principal_class}` series start at
zero. Plain selector queries and `sum by (method, status)` keep working;
re-baseline any dashboard or alert that matches the exact label set or joins
on series identity.

## ⚠️ Breaking: account lockout is ON by default

This release adds account lockout for failed **local-password** logins (SOC 2
CC6.3) and it is **active by default** (`--auth-lockout-threshold=5`,
`--auth-lockout-window-secs=900`) **on any deployment that runs with a
persistent auth database** — i.e. one started with `--data-dir`.

> **⚠️ `--data-dir` is required.** Lockout state lives in the persistent
> `auth.db`, which only exists when the server is started with `--data-dir`.
> The shipped **container images and compose files** pass `--data-dir
> /var/lib/yuzu`, so lockout genuinely is on by default there. The
> **systemd/.deb** unit now also passes `--data-dir /var/lib/yuzu` (added in
> this release) — but if you run a **custom invocation** without `--data-dir`,
> the server falls back to in-memory auth and lockout (and session persistence)
> is silently **off**. The server logs a loud startup `WARN` in that state.
> Set `--data-dir` to make the control active.
>
> **Superseded by the AuthDB→Postgres migration (see below).** Lockout state
> now lives in **Postgres** (`users.failed_login_count` / `locked_until`), not
> `auth.db`. It is active whenever `--postgres-dsn` (or `YUZU_POSTGRES_DSN`) is
> set — which the server now **requires to boot at all** (no SQLite fallback) —
> and `--data-dir` no longer gates it. Read the `--data-dir` requirement above
> as historical, for pre-migration builds only.

No further config change is required to opt in — a deployment that already runs
with `--postgres-dsn` gains the behavior the instant you start the new build.

What changes on upgrade:

- After **5 consecutive failed `POST /login` attempts** a local-password account
  is locked for **15 minutes**. While locked, every login attempt — *including
  one with the correct password* — returns the **same generic 401 as a bad
  password** (no `Retry-After`, no "you are locked" message; this is deliberate,
  to avoid a username-enumeration / lock-state oracle).
- The lock **auto-expires** after the window — it is never permanent — and a
  user who waits it out regains a full attempt budget.
- Scope is **local-password only**. SSO/OIDC logins (throttled by your IdP) and
  API/automation tokens are **unaffected** — no automation breakage.

**Highest-risk targets** on upgrade: shared or service accounts that log in with
a password, and any password-rotation / monitoring automation that may submit a
stale password in a loop — these can now lock themselves out where previously
nothing happened.

**Before upgrading, do ONE of:**

1. Accept the default (recommended for most) — it closes a real
   credential-stuffing surface. Make sure operators know the recovery path
   below.
2. Raise the threshold if you also rate-limit at the network layer
   (NIST 800-63B §5.2.2 suggests ≥10): `--auth-lockout-threshold=10`.
3. Disable it (not recommended; constitutes a deviation from the CC6.3 hardened
   baseline): `--auth-lockout-threshold=0` (the server logs a startup `WARN`).

**Recovery if an account is locked out:**

- Another admin can clear it immediately:
  `POST /api/v1/users/{username}/unlock` (`UserManagement:Write`, MFA step-up).
- Or wait out the window (default 15 min).
- **Single-admin deployments:** there is no self-service unlock for the *only*
  admin (the unlock endpoint requires a second privileged principal), so either
  wait out the window or use the offline recovery procedure in
  `docs/ops-runbooks/auth-db-recovery.md` § Account lockout recovery. That
  runbook is now Postgres-native throughout: its fallback clears
  `failed_login_count` / `locked_until` with `psql "$YUZU_POSTGRES_DSN"`
  against `auth.users`, which is exactly the sole-admin case. It writes no
  audit row, so record it in your change-management system.

## Behaviour change: operator/API tags now beat agent self-report (#1411)

An agent's self-reported tags (`scopable_tags`, synced on every Register) can no
longer overwrite an operator- or API-set tag for the same `(agent_id, key)` — the
operator/API value is now authoritative. This closes a path where a rogue or
misconfigured agent could self-assign into an operator-declared benchmark cohort.

**Who this affects:** only an operator who *deliberately* relied on agent-reported
values winning over an operator/API-set tag for the same key. After upgrade those
agent values stop overriding — silently (no error, no log line); an affected device
simply drops out of the cohort the operator-set value defines.

**Verify:** audit the `source` field via MCP `get_tags` — `GET /api/v1/tags` does not
expose `source`, only `key`/`value` pairs (see the read-side note below) — to see whether
each key is `api`/`mcp`-sourced (operator/API) or `agent`-sourced.

**Read-side completion (#3295):** #1411 closed the write-time overwrite; scope-DSL
`tag:<key>` evaluation (dispatch targeting, management-group membership) had its own,
separate precedence — a currently-connected agent's live self-report answered before the
store was even consulted. That is now also store-first: an operator/API-set row always
wins for scope-DSL purposes too, and an agent-claimed `service` value never answers from
the live self-report at all (it is dropped at registration, not just at store sync).
**Who this affects:** an operator who deliberately relied on a live agent's tag value
overriding an operator/API-set tag specifically for dispatch targeting or cohort
membership while that agent stayed connected. See `docs/asset-tagging-guide.md` "Tag
source precedence (read time, scope-DSL, #3295)".

**Caution:** the `/devices` tag-chip display is unaffected by this change and can now
visibly disagree with what actually governs targeting: it renders only the agent's live
self-report, never the TagStore row, so a store value that now wins for dispatch
purposes — of any source, including a previously-synced agent value that's now stale
relative to the agent's live report, not only an operator-set one — may not be what the
dashboard chip shows. When a store row exists for the key, MCP `get_tags` (its `source`
field) is the source of truth for what governs a device's scope-DSL matching, not the
dashboard; `GET /api/v1/tags?agent_id=<id>` does not expose `source`. For a
gateway-proxied or not-yet-synced agent with no store row at all, the live self-report
(what the dashboard shows) is what actually governs — an empty `get_tags`/`GET
/api/v1/tags` result for a key means the live claim decides, not that nothing does.

**Remediate:** if an agent-reported value was the *intended* one, re-set it explicitly
via the REST API (writes `source=api`) or MCP `set_tag` (writes `source=mcp`) — either is
authoritative over an agent-sourced row. Keys the agent reports that the operator never
set are unaffected.

## Behaviour change: MCP approval-gated calls use ticket-then-recall (-32006) (#289)

Supervised-tier MCP tokens that attempt an approval-gated operation (e.g. `delete_tag`,
`quarantine_device`) now run through a **ticket-then-recall** approval flow. The first
call returns JSON-RPC error `-32006` (`ApprovalRequired`) whose `error.data` carries an
`approval_id` and a `status_url` (`GET /api/v1/approvals/{id}`). After a second principal
approves the ticket, the caller re-invokes the same tool with the `approval_id` and the
operation executes (the ticket is consumed exactly once, args-bound, replay-rejected).

> An earlier development iteration returned `-32004` (`TierDenied`) for these operations
> because the approval re-dispatch path was unbuilt. That intermediate behaviour **never
> shipped in a release** and is fully superseded by the flow above — there is no `-32004`
> approval-denial in the released product.

**Who this affects:** any MCP client that matched on the approval-gated denial. Match
`-32006` and read `error.data.approval_id` / `status_url` to drive the approval workflow;
`operator`-tier executions are auto-approved and are unaffected. On the REST transport an
approval-gated operation by an MCP-tier token is denied (there is no JSON-RPC ticket
channel on REST) — use the MCP `/mcp/v1/` flow or the dashboard.

Three review-round hardenings in the same release (PR #1796):

- **Supervised REST quarantine is now mirror-denied.** `POST /api/v1/quarantine` and
  `DELETE /api/v1/quarantine/{agent_id}` return `403` for a supervised-tier token. An
  operation-mapping mismatch previously let a supervised token quarantine via REST with
  **no approval** — if any automation relied on that, it was riding the bug; route it
  through the MCP `quarantine_device` ticket flow or use a non-tiered token.
- **Approved-but-unconsumed approval tickets expire after 7 days** (measured from the
  review). An approved ticket is a live one-time capability; it now ages out on the same
  window as unreviewed pending requests. Recalling an expired ticket returns the standard
  "approval was expired" denial — submit a fresh request.
- **`consumed_by` traceability column** (additive, auto-migrated): the approvals store
  records WHO recalled each consumed ticket alongside the existing `consumed_at`
  (SOC 2 CC7.2 evidence chain: `submitted_by` → `reviewed_by` → `consumed_by`).

## Behaviour change: `POST /api/v1/tokens` now honors `mcp_tier`

The token-mint endpoint now applies the `mcp_tier` field from the request body
(`readonly` / `operator` / `supervised`). Previous releases **silently dropped**
it: a token requested with an `mcp_tier` was stored **tier-empty** (RBAC-deferred),
which means it was *over-privileged* relative to the tier the operator intended —
a `readonly` request behaved as a full RBAC-scoped token, not a read-only MCP
token. The endpoint also now validates at mint time: an unrecognised tier, or a
tiered/service-scoped token whose `expires_at` is missing or more than 90 days
out, returns `400` (previous releases returned a misleading `503`).

**Who this affects:** any operator who minted an MCP token via `POST /api/v1/tokens`
**before** this upgrade and relied on the `mcp_tier` to constrain it. Those tokens
are still tier-empty and therefore broader than the requested tier.

**Remediate:** **rotate any pre-upgrade `mcp_tier` tokens** — revoke the old token
(`DELETE /api/v1/tokens/{id}`) and re-mint it; the new token stores the tier and is
constrained as intended. Tokens minted with no `mcp_tier` are unaffected.

**Additive (no operator action required):** the `discover_plugins` discovery response
(REST `GET /api/v1/discover/plugins` and the MCP tool) is now `version: 2` — it adds an
inline `parameter_schema` per action (where a published `InstructionDefinition` exists and
the caller holds `InstructionDefinition:Read`) plus a top-level `actions_enriched_with_schema`
count. The change is purely additive; any client that pinned `version == 1` should relax the
check to a minimum (`>= 1`).

## ⚠️ Breaking: API and MCP bearer tokens are invalidated on upgrade (ApiTokenStore → Postgres, ADR-0030)

`ApiTokenStore` — the store backing every `Authorization: Bearer` API token and
every MCP token — moves from SQLite (`api-tokens.db`) to the server's PostgreSQL
substrate in this release (engine-principals PR 4.1; ADR-0006/ADR-0030). This is
a **fresh-start cutover with no data migration**: the new server creates an empty
Postgres `api_token_store.api_tokens` table and **never reads the old
`api-tokens.db`**, so every API/MCP token minted before the upgrade stops working
the instant the new server starts. Interactive cookie-session login (dashboard,
OIDC/SAML SSO) is **not** affected — only bearer tokens.

The rationale for no backfill (convention with every prior server-store migration,
plus the token store holds only verify-only hashes) is in ADR-0030.

**Who this affects:** every external automation consumer that authenticates with an
API or MCP bearer token — CI/CD scripts, SIEM/webhook pollers, cron jobs, MCP
clients. Because it is a fresh-start cutover, **all of them break at once** at the
moment of upgrade; there is no rolling/staged token continuity.

**Remediate:** after upgrading, **re-mint every API/MCP bearer token** (`POST
/api/v1/tokens`) and update the credential wherever it is stored (CI secrets, cron
configs, MCP client configs). Plan the upgrade in a **maintenance window** and
**notify automation/integration owners in advance** so a batch of `401`s across
every integration is expected, not a surprise incident.

**Diagnostic:** if the legacy `api-tokens.db` is still on disk, the server logs
`[auth] Legacy SQLite api-tokens.db found at … — API/MCP tokens now live in
PostgreSQL and any prior tokens were INVALIDATED by the migration (ADR-0030)` at
boot. The old file is inert (never read again) and can be removed once you have
re-minted; it contains only token hashes + metadata, no plaintext secret.

**Multi-instance note:** the Postgres substrate now permits running multiple server
replicas against one database. Token *validation* uses a per-process 60-second
cache, so a token revoked on one replica may remain accepted on another replica for
up to that window — see ADR-0030 for the tracked hardening.

## ⚠️ Breaking: `engine:` namespace reservation — server refuses to start on a pre-existing collision (engine principals PR 4.2)

This release introduces the **engine principal** class — a distinct identity
class for autonomous/agentic callers, stored in the new `EnginePrincipalStore`
and resolved through RBAC/`ApiTokenStore` (design doc §3.1/§3.3). To make that
resolution unambiguous, the `engine:` prefix is now a **reserved namespace**
for both local usernames (`users.username`) and local RBAC group names
(`groups.name`).

**Pre-upgrade collision check** (mirrors the plugin-trust-bundle filename
collision check above). At boot, the server now scans for any pre-existing
`engine:`-prefixed local user or local RBAC group and **refuses to start** if
it finds one — silently coexisting with (or being shadowed by) a real engine
principal is not an acceptable outcome, so this fails closed rather than
booting into an ambiguous state (decision log #3). Before upgrading, run
against both stores.

> **Superseded by the RbacStore → PostgreSQL migration (ADR-0041):** the
> per-node `sqlite3 rbac.db` query below is a HISTORICAL artifact from the era
> when local RBAC groups were SQLite. RBAC config is now a **single shared
> PostgreSQL** `rbac_store` schema, so run **one** `psql` query, **not**
> per-node `sqlite3`. Both queries below target Postgres:

```bash
# Local users — Postgres.
psql "$YUZU_POSTGRES_DSN" -c \
  "SELECT username FROM auth.users WHERE username LIKE 'engine:%';"

# Local RBAC groups — PostgreSQL (shared; one query, not per-node — ADR-0041).
psql "$YUZU_POSTGRES_DSN" -c \
  "SELECT name FROM rbac_store.groups WHERE source = 'local' AND name LIKE 'engine:%';"
```

If either query returns rows, rename or remove those users/groups **before**
upgrading — the new server will not boot until the collision is cleared (or,
if the boot-time collision scan itself fails, e.g. a mid-scan database error,
the server also fails closed rather than guessing). See
[`docs/ops-runbooks/engine-principal-store-recovery.md`](../ops-runbooks/engine-principal-store-recovery.md)
for the full recovery procedure if you hit this at boot.

**Scope of this release:** PR 4.2 ships the engine-principal store, RBAC
resolution, and attribution plumbing only — there is **no operator-facing
surface yet** (no dashboard/REST CRUD for minting or managing engine
principals). That ships in PR 4.3.

## ⚠️ Breaking: `--mfa-enforcement` now enforces

Releases before this one accepted `--mfa-enforcement=admin-only` and
`--mfa-enforcement=required` but treated them as **no-ops** (the parser
accepted the value for forward-compat and the server emitted a startup
`WARN`). **This release makes them enforce.** If you staged the flag based
on that prior documentation, enforcement goes live the instant you start
the new build.

What changes on upgrade if the flag is set to `admin-only` or `required`:

- An **un-enrolled** user covered by the mode can no longer log in directly.
  `POST /login` returns a 202 `mfa_enrollment_required` challenge and the
  user must complete TOTP enrollment (scan QR → enter first code at
  `POST /login/mfa/enroll`) before a session is minted. This is a no-lockout
  bootstrap, **but** it requires the user to enroll at their next login.
- The startup log line for non-default modes changes from `WARN` (no-op) to
  `INFO` (enforcement active).
- An operator can no longer disable their own MFA while the mode protects
  their role.

**Before upgrading with the flag set, do ONE of:**

1. **Recommended:** leave the flag at `optional`, upgrade, have all affected
   users enroll (Settings → Security and sign-in → Two-factor sign-in), *then* set
   `admin-only`/`required` and restart. or
2. Upgrade with the flag set and accept that affected un-enrolled users will
   be walked through enrollment on their next login.

**SSO / OIDC pre-flight (required reading if you use SSO):** under
`required` (and `admin-only` for admin SSO users), OIDC sessions are
MFA-gated by the IdP's `amr` claim — an SSO login the IdP did **not** MFA
is blocked from high-risk endpoints (it must re-authenticate via SSO),
symmetric with a local user being forced to enrol. Yuzu cannot mint a
second factor for an external identity, so **before enabling
`required`/`admin-only` with SSO you MUST verify your IdP asserts an `amr`
claim containing a recognized MFA method** (Entra: `mfa`; others:
`otp`/`hwk`/etc., RFC 8176). If it does not, affected SSO users will be
unable to reach high-risk endpoints — recoverable by restarting in
`optional` (see `docs/ops-runbooks/auth-db-recovery.md` § "Locked out by MFA
enforcement misconfiguration"; that runbook is now Postgres-native throughout).
Under `optional`, no IdP `amr` configuration is required (SSO sessions pass
the gate).

**Single-admin deployments:** do not first-boot a fresh single-admin
deployment straight into `required`. Enroll the admin under `optional` first,
then switch. If you do start with `required`, the admin must complete
login-time enrollment within `--mfa-login-pending-secs` (default 120s); if
the token expires, restart with `optional`, log in, enroll, then re-enable.

**Recovery if you get locked out** (IdP doesn't assert `amr`, or the sole
admin can't enroll): restart the server with `--mfa-enforcement=optional`
(this re-seeds the in-memory config), log in, resolve enrollment, then
re-enable. See `docs/ops-runbooks/auth-db-recovery.md` — that runbook is now
Postgres-native throughout, so both the restart procedure above and its SQL
steps apply as written to a Postgres-backed AuthDB.

## Hardened auth mode (`--auth-mode=sso-only`) — opt-in (SOC 2 CC6.3/CC6.6)

**No operator action on upgrade.** Existing deployments default to
`--auth-mode=standard` and behave exactly as before. This release adds the
*option* to disable local-password login fleet-wide so only an SSO provider can mint a
session.

If you intend to enable `sso-only`, do this **first** — the server **fails
closed (non-zero exit, refuses to serve)** otherwise:

1. Configure OIDC (`--oidc-issuer` + the related flags) and confirm SSO works in
   `standard` mode. `sso-only` without an SSO provider (OIDC, or a complete SAML
   SP config on Linux/macOS with HTTPS) refuses to start (it would lock every
   operator out).
2. (Recommended) Create a single break-glass local account and **enroll MFA on
   it** (Settings → Security and sign-in → Two-factor sign-in). Point `--break-glass-user` at
   it. `sso-only` refuses to start if the named break-glass user doesn't exist or
   has no MFA enrolled — a break-glass account must carry a second factor.
3. Restart with `--auth-mode=sso-only`. Local-password login is now rejected for
   everyone except the break-glass account, and only **while armed**.

**Breaking the glass (IdP outage).** The break-glass account is dormant until
armed out-of-band on the server host: `yuzu-server --break-glass-arm
--break-glass-user <name> --config … --data-dir … --postgres-dsn …` arms it for
`--break-glass-window-secs` (default 24 h, auto-expiring). It still requires the
account's MFA at login. Since the AuthDB→Postgres migration this one-shot opens
the **Postgres** auth store, so `--postgres-dsn` (or `YUZU_POSTGRES_DSN`) is
**required** — point it at the same database the server uses; without it the
command fails closed with "requires the Postgres auth store" and does nothing.
`--data-dir` is still needed for the audit record. Full runbook:
`docs/ops-runbooks/auth-db-recovery.md` § Break-glass arm (that runbook is now
Postgres-native throughout).

**Migration.** `break_glass_armed_until` is a nullable column on `auth.users`.
It arrived as SQLite `auth.db` migration v4, but the AuthDB→Postgres cutover
folded every historical migration into the born-on-PG schema, which starts at
**v1** — there is no v4 to apply and no rollback-past-v4 question. See the
AuthDB→Postgres section above for the (fresh-start, no-backfill) upgrade
contract that replaces it.

## ⚠️ Breaking: server generates default TLS certificates on first boot (v0.13.0)

Before v0.13.0 the server **refused to start** without operator-provided certs
(or `--no-tls`/`--no-https`). From v0.13.0, when a TLS surface has no certs the
server **auto-generates a per-install ECDSA CA + leaf certs** on first boot and
serves encrypted with no operator action.

Impact by prior configuration:

| Prior startup flags | After upgrade |
|---|---|
| `--cert`/`--key` (+ `--https-cert`/`--https-key`) supplied | No change — operator certs always win; defaults are never generated for a supplied surface. |
| `--no-tls --no-https` (plaintext dev) | No change — both surfaces disabled; no certs generated. |
| `--no-tls` only (HTTPS previously errored without certs) | **HTTPS now serves an auto-generated default cert** instead of failing. The agent surface stays plaintext. |
| No cert flags (previously refused to start) | **Now starts, encrypted, on default certs**, with a loud banner. |

What to expect / do:

- **Browsers show an untrusted-issuer warning** for the dashboard until you trust
  the per-install CA (`<ca-dir>/default-ca.pem`, default `/etc/yuzu/certs`) or
  replace the cert with `--https-cert`/`--https-key`. The connection is encrypted;
  only issuer verification is missing.
- **Agents:** while on default certs the agent listener is encrypted but does
  **not require** client certs (per-agent mTLS arrives in a later release).
  Agents that previously connected over plaintext must switch to TLS — point them
  at the CA with `--ca-cert <ca-dir>/default-ca.pem`.
- **To keep the legacy refuse-to-start behaviour**, pass `--no-default-certs`.
- **Back up `<ca-dir>/default-ca.key` (0600) and the `ca_store` Postgres schema**
  (`pg_dump`/`pg_restore`, ADR-0053) — losing the CA key forces a full fleet
  re-enrollment.
- Relocate the cert directory with `--ca-dir` (e.g. a dedicated container volume).

## Generic inventory store no longer reads or scrubs a legacy `inventory.db` (ADR-0037)

`InventoryStore`'s one-time first-boot backfill from a legacy `inventory.db` SQLite file
(`migrate_from_sqlite()`) has been retired (#3623) — no production fleet ever ran a
pre-Postgres build, so there was no real legacy data to migrate. Two separate behaviors changed:

- A reachable Postgres database whose schema can't migrate or open **is** still a fatal startup
  error (fail-closed), same as before.
- A legacy `inventory.db` file with real content **does NOT** fail startup and its content is
  **never imported** — the server opens it read-only, purely to count rows in `inventory_data`
  for a diagnostic warning, then boots regardless of what it finds.
- **`delete_agent()` no longer erases anything from a legacy `inventory.db` either** — the
  previous "erase from Postgres AND the retained legacy SQLite copy" behaviour is gone. A
  leftover legacy file is inert: never read on boot beyond the diagnostic warning above, and
  never scrubbed by a device decommission. If your environment genuinely still has a legacy
  `inventory.db` you need gone (e.g. for a completed decommission's data-retention obligations),
  delete it manually.

**Verify:** after the server reports ready, generic inventory reads (`GET /api/v1/inventory` or
equivalent) behave exactly as before — this store's runtime read/write/query behavior is
unchanged, only the one-time backfill and the legacy-file erasure are gone.

**Rollback caution.** Rolling back to a build older than this release, against a database that
has already run this store's retirement migration, **unconditionally** fails that older
binary's boot with a Postgres `undefined_table` error on its own idempotency-marker check — not
only when a legacy `inventory.db` happens to be present. This is a deliberate fail-safe (a clear
startup error, never silent data loss), not a bug, but it means "just roll back the binary" is
not a supported recovery path once this migration has run. The same is true for
CaStore/ManagementGroupStore/QuarantineStore/WebhookStore below, each for its own dropped marker
table. RbacStore is the one genuine exception (see its own section): its retirement migration
**poisons** the marker rows to a sentinel value rather than deleting them, so an old binary's own
lookup finds them present (not 0 rows) and — reading a value it understands as "no verified
source, but not a failure" — boots normally UNLESS a real, unmigrated legacy file is also present
on that specific host. This is RbacStore's own deliberate choice to tolerate rollback, not an
artifact of a row count. AuditStore also removes marker rows rather than dropping a table, but do
NOT assume it behaves the same way as either group — its own section explains why an old binary's
boot fails just as reliably as the DROP-TABLE group's, via a CHECK constraint rather than a SQL
error on a missing table.

## ⚠️ Behaviour change: internal-CA store moves to Postgres (ADR-0053)

`CaStore` (internal-CA root metadata, issued-certificate inventory, CRL version
history — everything the mTLS-accept revocation gate and `GET /api/v1/ca/*`
read) moves from the SQLite `ca.db` file to the server's PostgreSQL substrate
in this release (schema `ca_store`). The private CA root key is unaffected —
it was never in `ca.db` and stays a local file behind `KeyProvider` (`--ca-dir`).

- **No legacy-SQLite migration path.** No production fleet ever ran a
  pre-Postgres build of this store, so there was no real `ca.db` data to carry
  over — the one-time backfill this section originally described was retired
  under ADR-0009's fresh-start-by-default amendment (see ADR-0053's Update). A
  reachable Postgres database whose schema can't migrate or open is still a
  fatal startup error (fail-closed); a legacy `ca.db` file with real content
  does NOT fail startup and its content is never imported — the server opens
  it read-only, purely to count rows in `ca_root`/`ca_issued`/`ca_crl_versions`
  for a diagnostic warning, then boots regardless of what it finds.
- **New fail-closed-at-boot behaviour.** A genuine Postgres error while wiring
  the per-agent mTLS revocation checker at boot now refuses to start the
  server, rather than starting with revocation enforcement silently unwired.
  If the server previously started cleanly on a working Postgres connection,
  this changes nothing observable; it only changes what happens during a
  Postgres outage at exactly that boot step, from "starts degraded" to
  "refuses to start."
- **`GET`/`POST /api/v1/ca/*` and the CA MCP tools now return a `503`/internal
  error on a genuine database error**, instead of a silently-empty or
  silently-false result.
- Every other CA behavior — revocation semantics, CRL numbering, the single
  `sign_agent_csr` chokepoint — was unchanged by that migration. CRL numbering and
  publication were later reworked for multiple server replicas (HA WS-6 slice 6.1):
  see `docs/user-manual/server-admin.md` "vNEXT — CRL publishing is serialised in
  Postgres". Detail: `docs/pki-architecture.md`,
  `docs/adr/0053-ca-store-postgres-migration.md`.
- **Rollback caution:** see the InventoryStore section's "Rollback caution" note above — the
  same unconditional rollback-refusal applies to this store (its own dropped marker table).
- **New: an established, already-running default-cert install can now self-heal
  its own listener leaves without operator action.** This is not limited to a
  first-boot crash window — any boot where the on-disk `--ca-dir` default
  leaves are missing, corrupt, or a leaf was later lost (a bad partial restore,
  a lost volume file) hits the same path, as long as `ca_store` already holds
  a root and this instance's local CA key file still matches it. When that
  holds, the server automatically **re-mints its own https/server/gateway
  leaves with fresh private keys** under the existing root and resumes,
  instead of refusing to start. It never touches the CA root itself or any
  agent-issued certificate. Every occurrence logs a `spdlog::warn` line, but
  there is currently no dedicated audit-log row for it (unlike enrollment-time
  `ca.cert.issued`) — tracked as a follow-up, not fixed in this release.
- **HA note: a losing first-boot replica self-heals within the same boot attempt
  (UP-3), bounded.** Multiple server instances sharing one `--ca-dir` cert
  volume and one `ca_store` Postgres substrate is not an officially supported
  deployment topology today (see ADR-0053's Decision section) — this note
  describes what happens if it's done anyway, safely, not a recommendation to
  do it. If two instances start against the same fresh `ca_store` at once,
  exactly one wins the root race and generates the live default certs; the
  other polls the shared cert directory for up to 15s for the winner's
  complete set to land (it only adopts a fully-written set — the winner's
  completion marker is written last, so a partial/in-flight write is never
  picked up) and, on success, continues booting on the winner's certs without
  a restart. If the winner hasn't finished within that window (a slow
  Postgres, lock contention, or a winner that's itself still starting up), the
  loser falls back to the original behavior: it **exits** (refuses to start,
  non-zero) rather than serving with its own discarded material — it does not
  reach a running-but-unready state, so a readiness-probe-driven restart never
  applies here. Recovery in that case is a plain process-supervisor restart
  (systemd `Restart=on-failure`, Kubernetes `restartPolicy`) once the winner's
  certs are in place, so the losing instance picks them up from disk on its
  next boot attempt. On systemd specifically, a slow winner (e.g. Postgres
  itself under load) can interact with the crash-loop guard
  (`StartLimitBurst`/`StartLimitIntervalSec`) — a losing replica that exhausts
  its restart budget first lands in the service's "failed" state and needs a
  manual `systemctl reset-failed` once the winner has actually finished,
  rather than retrying forever on its own. Diagnosing a bootstrap that seems
  permanently stuck (neither replica ever finishes): check `pg_locks` for a
  lingering `yuzu:default_certs_bootstrap` session advisory lock with no live
  backend behind it (a host crash or network partition can leave one held
  until Postgres notices the dead session) and `pg_terminate_backend` it — see
  `docs/pki-architecture.md`'s operator runbook.

## ⚠️ Behaviour change: webhook store moves to Postgres (ADR-0057)

`WebhookStore` (operator-registered outbound webhooks and their delivery log —
everything behind `GET`/`POST`/`DELETE /api/webhooks` and
`GET /api/webhooks/{id}/deliveries`) moves from the SQLite `webhooks.db` file
to the server's PostgreSQL substrate in this release (schema `webhook_store`).
The webhook HMAC signing secret is now envelope-encrypted at rest
(`SecretCodec`, AES-256-GCM, ADR-0010) instead of a plaintext column.

- **No legacy-SQLite migration path.** No production fleet ever ran a
  pre-Postgres build of this store, so there was no real `webhooks.db` data
  to carry over — the mandatory, both-tables backfill this section originally
  described was retired under ADR-0009's fresh-start-by-default amendment
  (see ADR-0057's Update). A reachable Postgres database whose schema can't
  migrate or open is still a fatal startup error (fail-closed); a legacy
  `webhooks.db` file with real content does NOT fail startup and its content
  is never imported — the server hardens it to 0600 (main file and any
  `-wal`/`-shm`/`-journal` sidecars, since it may still hold a pre-cutover
  signing secret in plaintext — POSIX only, a no-op on Windows, #3593) and
  counts rows in `webhooks`/`webhook_deliveries` for a diagnostic warning, then
  boots regardless of what it finds. There is no move-aside: the legacy
  file stays at its original path.
- **New fail-closed-at-boot behaviour.** A Postgres/`SecretCodec` error at any
  point in this store's boot sequence (schema migration or KEK verification)
  now refuses to start the server, rather than starting with webhooks
  silently unwired.
- **If you have a real `webhooks.db` you need re-imported:** there is no
  automated recovery path — recreate the webhooks (and, if used, their
  signing secrets) via `POST /api/webhooks` after the server starts. See
  [`rest-api.md`](rest-api.md#post-apiwebhooks) for guidance on securely
  disposing of a legacy file that still holds a plaintext secret.
- **If you already upgraded through an EARLIER release** (one where the
  now-retired backfill genuinely ran), check for a `webhooks.db.migrated-
  <unix-epoch>` file (and its `-wal`/`-shm` sidecars) at the same directory —
  that historical rename-on-success behavior is gone in this release (a
  legacy file is never renamed any more), but a file it already produced is
  NOT cleaned up by this upgrade and still holds every pre-cutover signing
  secret in **plaintext**. Dispose of it securely if you no longer need it;
  the current probe only checks the un-renamed `webhooks.db` path, so it will
  never warn about a `.migrated-<epoch>` file left over from before.
- **Rollback caution:** see the InventoryStore section's "Rollback caution" note above — the
  same unconditional rollback-refusal applies to this store (its own dropped marker table).
- **`POST`/`DELETE /api/webhooks` now distinguish a caller error from a store
  failure**: `POST` returns `400` for an invalid URL scheme (previously an
  ambiguous non-error response), and `GET`/`POST`/`DELETE /api/webhooks`
  (list/create/delete) return `503` on a genuine database error instead of a
  silently-empty or silently-failed result. `GET /api/webhooks/{id}/deliveries`'s
  degrade-vs-error handling specifically is unchanged by this migration — a
  degraded read there still renders an empty delivery list rather than a
  `503`, the same as before the cutover.
- **`GET /api/webhooks/{id}/deliveries`'s `?limit=` handling changed.**
  `limit=0` (or any non-positive value) previously meant "return zero rows";
  it now falls back to the default of 50, the same as an omitted `limit`. A
  value above 10000 was previously passed through unbounded; it is now
  silently capped at 10000. If your integration relies on `limit=0` meaning
  "give me nothing," or on retrieving more than 10000 rows in one call,
  update it.
- Every other webhook behavior — event-type matching, HMAC-SHA256 signature
  format (`X-Yuzu-Signature: sha256=<hex>`), unsigned delivery when no secret
  is configured — is unchanged. Detail:
  `docs/adr/0057-webhook-store-postgres-migration.md`.

## ⚠️ Behaviour change: response history resets on Postgres cutover (ADR-0039)

`ResponseStore` (agentic command/instruction results — the executions drawer
and TAR read source) moves from the SQLite `responses.db` file to the server's
PostgreSQL substrate in this release (ADR-0006 Wave 1, schema `response_store`).
Like the `ApiTokenStore` and AuthDB cutovers, this is a **fresh-start cutover
with no data migration** — response results are expendable, TTL'd telemetry
(ADR-0009 skippable backfill), so the legacy `responses.db` is **never read** on
upgrade.

**What happens on first PG boot:**
- The server logs a one-time `response history reset on Postgres cutover`
  warning.
- Executions-drawer and TAR views for commands issued **before** the cutover
  are empty; results for commands issued after are unaffected and refill
  immediately as agents report.
- No operator action required. To preserve pre-cutover response history,
  export it from the old `responses.db` before upgrading (see
  `docs/user-manual/response-store.md` → periodic exports).

**Also in this release:** non-UTF-8 bytes in a plugin's output/error (which
the old SQLite `TEXT` column tolerated but PostgreSQL `TEXT` rejects) are now
replaced with the Unicode replacement character (U+FFFD) at ingest — the
response row is still stored and still renders, defanged, rather than being
dropped (governance #1593). Retention moved from an hourly background thread
to a clock-guarded, capped reap on the maintenance tick (no operator-visible
behaviour change beyond the same 90-day default).

## ⚠️ Behaviour change: directory sync state resets on Postgres cutover (ADR-0063)

`DirectorySync` (AD/Entra ID integration — synced users/groups, group
memberships, and group→role mappings) moves from the SQLite
`directory-sync.db` file to the server's PostgreSQL substrate in this release
(migration-programme PR 3, schema `directory_sync`). This is a **fresh-start
cutover with no data migration** (ADR-0009) — the legacy `directory-sync.db`
is **never read** on upgrade.

**What happens on first PG boot:**
- The server logs a one-time `DirectorySync initialized (schema
  directory_sync) — fresh start, no legacy backfill` line, and a separate
  warning naming a row count if the legacy `directory-sync.db` still holds
  synced users/groups/mappings.
- `GET /api/directory/users`, `GET /api/directory/status`, and the group→role
  mapping list all start empty.
- **Before upgrading, capture your current group→role mappings** (they will
  NOT survive the cutover): `PUT /api/directory/group-mappings` with an empty
  `{"mappings": []}` body is a safe, non-mutating read — an empty input array
  is a no-op, and the response always echoes the store's full current
  mapping list regardless. There is no dedicated read-only endpoint for this
  today; save the response's `mappings` array (each entry
  `{"group_id": "...", "role_name": "..."}`) somewhere durable before you
  upgrade.
- **Operator action required, after upgrading:** re-run `POST /api/directory/sync` with the
  same `tenant_id`/`client_id`/`client_secret` you already supply on every
  sync call — this store never persisted the credential, so this migration
  adds no new credential-gathering step, but you still need it in hand to
  re-populate synced users and groups. Then re-apply every mapping you saved
  above via one `PUT /api/directory/group-mappings` call with body
  `{"mappings": [{"group_id": "...", "role_name": "..."}, ...]}` — those
  mappings ARE lost by the cutover and must be recreated from your saved copy.
  **Verify the re-sync captured everything**: compare `GET
  /api/directory/status`'s `user_count`/`group_count` against your Entra
  tenant's own user/group counts before considering the upgrade complete.
- The MCP `export_access_review`/REST access-review export's optional email
  enrichment (matched off synced users' UPN) is unaffected in shape — it
  degrades to "no enrichment" until the first post-upgrade sync completes,
  exactly as it already did whenever directory sync was never configured.

**Also in this release:** `directory_memberships` gained a real foreign key
(`ON DELETE CASCADE` on both `user_id` and `group_id`) — the SQLite era had
none. `/readyz` and `/healthz` now report `directory_sync` — the SQLite-era
store was never checked at boot or reflected in either probe.

**Behaviour change beyond the storage cutover itself:** a user or group
deleted from Entra now actually disappears from `DirectorySync` on the next
successful sync — the SQLite era kept every previously-synced user/group
around forever, upserting but never removing one Entra had deleted. If your
integration (or a saved report) relied on a removed identity remaining
visible via `GET /api/directory/users`/`GET /api/directory/status` after
leaving Entra, it will stop being visible starting with the first
post-upgrade sync. Relatedly, a malformed/unexpected Microsoft Graph groups
API response is now a hard sync failure (surfaced in
`GET /api/directory/status`'s `last_error`) rather than a silently-empty
group sync — this closes a gap the deletion behavior above would otherwise
have introduced (a transient Graph glitch wiping every synced group).

## ⚠️ Behaviour change: schedules, approvals, and execution history reset on Postgres cutover (ADR-0065)

`ScheduleEngine`, `ApprovalManager`, and `ExecutionTracker` move from the
shared SQLite `instructions.db` file (via `InstructionDbPool`) to their own
independent PostgreSQL schemas in this release (migration-programme PR 5,
the last of the components the postgres-migration ladder had never tracked
— `WorkflowEngine`/ADR-0064 having already made the same move in PR 4 —
schemas `schedule_engine`, `approval_manager`, `execution_tracker`
respectively). This is a **fresh-start cutover with no data migration**
(ADR-0009) — the legacy `instructions.db` is **never read** for data on
upgrade. `InstructionDbPool` itself is deleted; `instructions.db` is retired
and no Yuzu store writes to it again.

**Before upgrading, capture what you'll lose** (none of it carries over):
`GET /api/schedules`, `GET /api/approvals`, and `GET /api/executions` are
safe, non-mutating reads — use them to record your active recurring
schedules and any outstanding (pending or approved-but-unconsumed) approval
tickets before you cut over, so you know what to re-create afterward rather
than discovering gaps after the fact. `GET /api/executions` defaults to the
100 most recent rows (`?limit=<N>` to raise it — there is no offset/cursor
parameter) — for a fleet with more history than that, raise the limit
before relying on this as a full capture. **This capture step runs on the
pre-upgrade binary, which necessarily predates #3789** — the ADR-0065 Postgres cutover this
section documents shipped before #3789 did, so any binary old enough to still need this
procedure cannot yet carry #3789's `limit` cap; raise `?limit` as high as needed for this
specific step. (A binary that already carries #3789, by contrast, caps `GET /api/executions`'
`limit` at 500 regardless of the value requested, with no offset/cursor to page past it — see
`docs/user-manual/rest-api.md`'s "Executions" section — but that cap cannot bite on this
already-completed cutover's capture step.) The retired `instructions.db` file is **left on disk,
not deleted** — if you need to recover consumed-approval audit evidence
(the `submitted_by → reviewed_by → consumed_by` chain) after upgrading,
that file is the most complete source (the audit store also carries
`approval.approve`/`approval.reject` and `mcp.<tool>` consume events for
the same tickets, but not the full row); back it up separately before any
unrelated disk cleanup removes it, since Yuzu itself never will.

**What happens on first PG boot:**
- The server logs three one-time lines — `ScheduleEngine initialized (schema
  schedule_engine) — fresh start, no legacy backfill`, similarly for
  `ApprovalManager`/`approval_manager`, and `ExecutionTracker`/
  `execution_tracker` — plus a separate warning naming a row count for any
  of `schedules`/`approvals`/`executions`/`agent_exec_status` still present
  in the legacy `instructions.db`.
- `GET /api/schedules` starts empty. **Operator action required:** re-create
  any recurring schedules via `POST /api/schedules`.
- Any MCP or REST instruction-approval ticket pending, approved-but-unconsumed,
  or already consumed at the moment of cutover is gone. **Operator action
  required:** a pending approval must be re-requested by whatever flow
  originally submitted it (MCP `execute_instruction`'s approval gate, a
  scheduled run requiring approval, or a direct REST submission) — there is
  no way to recover an in-flight ticket across the cutover. Consumed-ticket
  audit history (the `submitted_by → reviewed_by → consumed_by` evidence
  chain) does not carry forward either.
- The executions drawer, REST execution routes (`GET /api/v1/executions/{id}`,
  `GET /api/v1/execution-statistics` + its `/agents`/`/definitions` sub-routes),
  and MCP execution-status tools
  (`get_execution_status`, `query_responses`'s execution-id join) all start
  empty. No gRPC `CommandResponse` in flight at the exact moment of upgrade
  has anywhere to land until the next dispatch. No operator action required
  — new executions populate normally from first boot.
- `/readyz` now lists all three stores (`ExecutionTracker` was already
  present, re-keyed off its own `is_open()` instead of the shared pool's);
  `/healthz` gains net-new `schedule_engine` and `execution_tracker` rows —
  neither was ever reported there before this release (`ApprovalManager` was
  already in both, unchanged).

**Also in this release:** `advance_schedule`'s locked select-then-compute-
then-update collapses into one atomic `UPDATE ... RETURNING`, closing a
two-statement race an app-level lock previously covered — no operator-visible
behavior change. `ExecutionTracker`'s one `sqlite3_changes()` call (gating
the terminal-transition SSE event on the shared SQLite connection) is closed
via `UPDATE ... RETURNING`, fixing a latent race under concurrent callers —
also no operator-visible change; the executions-history SSE contract
(progress-before-terminal event ordering) is unchanged. The MCP approval
error envelope's permanent-vs-transient discriminator changes internally
from a raw SQLite extended error code to a Postgres SQLSTATE string — the
same two response shapes are still chosen by the same rule, so no client
migration is needed.

## Behaviour change: `per-device` dispatch can now refuse a target it always accepted before (ADR-1007)

`ExecutionTracker` gains a new table, `concurrency_claims` (same
`execution_tracker` schema introduced above), backing real enforcement of
the `per-device` concurrency mode — the shipped default and the only one of
the five documented modes that was ever actually enforced (see
`docs/user-manual/instructions.md` §8 and ADR-1007 for the full
real-usage audit; `per-definition`/`global`/`global-singleton`/`per-set`
remain accepted but unenforced, unchanged from before this release).

**Operator-visible:** dispatching a `per-device` definition (via `POST
/api/instructions/:id/execute` or a `ScheduleEngine` run) to a device that
already has an execution of that same definition in flight now **excludes**
that device from the target list instead of sending a second, overlapping
command as it always did before. This is the intended fix, not a
regression — but any automation that dispatches the same definition
repeatedly in quick succession to the same fleet (e.g. a tight retry loop)
may see partial dispatch where it previously always saw full dispatch.
Watch the new `yuzu_server_dispatch_concurrency_skipped_total` counter (or
`ExecutionTracker::claim_concurrency_slots`'s `spdlog::info` line, which
reports a count — how many of the dispatch's candidates were already busy
for the definition — not individual device ids) to see when this fires —
the executions API's `agents_targeted` field is the post-claim SENT count,
not a pre-claim total, so there is no "targeted vs. claimed" comparison to
read it against. Error code `3003` (`ConcurrencyBlocked`) is registered for
this condition but not yet surfaced through the dispatch response.

Quarantining a device mid-flight (after it was claimed but before it
reports a terminal status) behaves the same as a crash for this purpose —
its claim ages out at the reconciler's TTL rather than releasing
immediately, so a device released from quarantine may still read as "busy"
for a `per-device` definition for up to that TTL window.

The claim's exclusion window is bounded by a flat one-hour timeout, renewed
by a dedicated agent-core keepalive that runs independently of any given
plugin — so a long-running `script_exec.*` action (a MUTATING instruction —
runs an operator-named program or authored script that can hold real state)
with an operator-configured timeout near the one-hour ceiling stays
correctly excluded even if it produces little or no output. The keepalive
sends one empty gRPC frame every 5 minutes per in-flight `per-device`
command — negligible traffic even at fleet scale, but worth knowing about
if you're diffing agent-to-server wire volume before/after this release.
See ADR-1007 for the full mechanism.

**Rolling-upgrade behaviour:** the keepalive lives in the agent binary, not
the server — during a staged agent rollout, a `per-device` command running
on an agent still on a build older than this release has no keepalive
thread, so its claim relies on the same rarer, less reliable renewal
signals this release replaces (a plugin's own output volume crossing an
internal threshold, or nothing at all for a quiet action). This is a
narrowing of a pre-existing exposure, not a new one — an old agent's
long-running quiet command was *always* at risk of this race before this
release; upgrading the server first only protects commands running on
already-upgraded agents. Upgrade agents promptly to get full coverage; per
the standing rule below, never upgrade agents before the server.

A claim is released when the excluded-from device's prior execution reaches
a terminal state; an execution that never gets a terminal response (agent
crash or disconnect mid-run) has its claim force-released by a periodic
reconciler, bounded by the claim's own `expires_at` — worst case, a device
can be excluded from a repeat `per-device` dispatch of the same definition
for up to one hour (a claim's lease is capped at one hour regardless of the
originating command's own expiry). **Cancelling an execution does not
release its claim** — there is no way to tell the agent to stop, so a
cancelled-but-still-running execution's claim behaves exactly like a normal
in-flight one until a terminal response or the reconciler's TTL bound
releases it. A `per-device` definition dispatched via a workflow step
(rather than a direct `POST /api/instructions/:id/execute` call or a
schedule) releases on the agent's real terminal response and renews on its
keepalive the same as every other dispatch path — workflow-step dispatch
still does not correlate a real execution id for the executions drawer
(so its progress won't show there), but that gap no longer affects claim
timing: it is not release-by-TTL-only. Raw MCP `execute_instruction` and
any other dispatch call that does not resolve an `InstructionDefinition`
are unaffected (no `definition_id` in scope, so this gate never fires for
them), as is the
fleet-broadcast dispatch arm. No operator action is required to upgrade.

**Also in this release:** `DirectorySync::sync_entra` (`POST
/api/directory/sync`) now rejects a concurrent call while a sync is already
in progress with `409 Conflict` instead of racing — previously two
overlapping sync calls could interleave writes. A caller that retries on
`409` behaves correctly; one that treated every non-2xx response as a hard
failure should special-case `409` as "try again shortly." `ConcurrencyManager`
(dead code with zero production callers, already flagged in
`docs/postgres-migration-ladder.md`) is deleted rather than migrated to
Postgres.

## ⚠️ Behaviour change: buffered analytics events reset on Postgres cutover (ADR-0049)

`AnalyticsEventStore` (the outbox spool behind `/api/analytics/status` and
`/api/analytics/recent` — login/MFA/OIDC/SAML/role-elevation and agent/gateway
command-lifecycle events, drained to any configured JSONL/ClickHouse sink)
moves from the SQLite `analytics.db` file to the server's PostgreSQL
substrate in this release (ADR-0049, Wave 2 batch 3, schema
`analytics_event_store`). Like `ResponseStore`, this is a **fresh-start
cutover with no data migration** — the buffer is a transient spool, not
authoritative or compliance evidence (ADR-0009 skippable backfill), so the
legacy `analytics.db` is **never read** on upgrade.

**What happens on first PG boot:**
- The server logs `[PG] analytics spool on Postgres ...` at info level — this
  line appears on every subsequent restart too (it states the store's
  steady-state configuration, not a one-time cutover event), so don't expect
  it to disappear after the first boot.
- Any events buffered but not yet drained to a sink at the moment of cutover
  are lost. In healthy operation this is bounded by the drain interval
  (10s default); if a sink was failing before the upgrade, whatever backlog
  had accumulated is lost too. Already-drained events were already delivered
  and are unaffected.
- New events buffer and drain normally from first boot. No operator action
  required.
- If analytics collection is disabled (`--no-analytics`), no store is
  constructed and no log line is emitted for it. If it's enabled but the
  schema fails to migrate, the server logs an error
  (`[PG] analytics-event store migration/open failed ...`) and the store
  stays constructed but degraded for that run (`is_open()==false`) — it
  keeps accepting `emit()` calls, which fail-soft and count a
  `store_not_open` drop, and `/api/analytics/status`/`/api/analytics/recent`
  return `503` rather than a `200`. Either way, a broken analytics store
  never blocks server startup (this store is the one Postgres-backed store
  on this ladder that does NOT fail the server closed on a construction
  failure; see ADR-0049) — `/readyz`'s `degraded` field (not
  `failed_stores`) names it when it's on but dead, without affecting the
  node's ready/not-ready status.
- **The store does not retry a failed open.** `is_open()` is latched once at
  construction — a Postgres blip that resolves moments after boot still
  leaves the store degraded for the rest of that process's uptime. Restart
  the server once Postgres connectivity for the configured DSN is confirmed
  restored; there is no in-process self-heal to wait out instead.
- **The Settings page's Enabled/Disabled analytics label is not accurate in
  the migration-failed case above** (governance Gate 6 finding, 2026-08-16) —
  it reads the `--no-analytics` config flag directly, not whether the store
  actually opened, so it can still say "Enabled" while a failed migration has
  left collection degraded for the run. Check `/readyz`'s `degraded` field
  or `GET /api/analytics/status` (`503 {"error":{"message":"analytics store
  degraded"}}` in this case — NOT `"enabled":false`, which is reserved for
  `--no-analytics`) for the accurate state, not the Settings page, until
  this is wired up.
- **Security note, separate from the cutover itself:** this release also
  fixes a pre-existing issue in the same store — `AnalyticsEvent.session_id`
  is now a hash of the session cookie, not the raw bearer token. If a token
  may have reached a shared analytics sink or a broadly-read analytics row
  before upgrading, see the rotation guidance in
  `changelog.d/20260816-analytics-session-id-hash.security.md` (assembled
  into the release's Security section at release time).

## RBAC store moves to PostgreSQL (RbacStore → Postgres, ADR-0041)

`RbacStore` — the authorization substrate holding **role definitions,
role→permission grants, principal→role assignments, RBAC groups + membership,
and the global `rbac_enabled` flag** — moves from the SQLite `rbac.db` file to
the server's PostgreSQL substrate in this release (ADR-0041, Wave 2.1), schema
`rbac_store`. No new flag or environment variable is added (it reuses the
shared server `PgPool`).

**No legacy-SQLite migration path.** No production fleet ever ran a
pre-Postgres build of this store, so there was no real `rbac.db` data to carry
over — the mandatory backfill this section originally described (including
the `rbac_enabled`-flag-first transfer and the move-aside/fingerprint-verify
mechanism) was retired under ADR-0009's fresh-start-by-default amendment (see
ADR-0041's Update). These are two SEPARATE behaviors, not one — do not
conflate them:

- A reachable Postgres database whose schema can't migrate or open **is**
  still a fatal startup error (fail-closed), unchanged from before.
- A legacy `rbac.db` file with real content **does NOT** fail startup and its
  content is **never imported** — the server opens it read-only, purely to
  count rows in `rbac_config` (the table that held the `rbac_enabled` flag),
  `securable_types`, `operations`, `roles`, `role_permissions`,
  `principal_roles`, `groups`, and `group_members` for a diagnostic warning,
  then boots regardless of what it finds. Fresh installs are unaffected — no
  legacy file, nothing to warn about.

**If you see the legacy-row-count warning and the environment genuinely has
real RBAC config to keep, there is no automated recovery path**: re-author
the equivalent roles/grants/groups against the new Postgres-backed store via
the RBAC admin UI/REST API, and re-check `rbac_enabled` after boot (it seeds
`false` on a fresh schema — it does NOT carry over from a legacy file, so an
operator who had RBAC enabled must re-enable it explicitly).

**Rollback caution.** Do not roll back to a build older than this release
while a legacy `rbac.db` file with real content still sits at its configured
path on any replica. An older binary's own (now-removed-from-current-code)
backfill logic still runs on that replica and, seeing this database already
past this migration, refuses to auto-migrate rather than silently doing
anything to `rbac_enabled` — you'll see a clear startup refusal, not silent
corruption, but it IS a startup refusal. Move the legacy file aside first if
a rollback is genuinely needed.

**What to expect / do:**

- **Routine (not just one-time) boot-time cost, every deployment.** Every
  server boot's `seed_defaults()` reseed now coordinates its built-in-default
  grants against any concurrent revoke via a cluster-wide advisory lock
  (closes a rare Postgres race where a revoked permission could otherwise be
  silently resurrected mid-boot). This adds a small, ordinarily negligible
  amount of boot time on every restart, not just first boot — but if you
  bulk-restart or scale out MANY replicas of the same RBAC-on-Postgres
  deployment **simultaneously**, their reseed passes serialize against each
  other, which can add up at large replica counts. Prefer a rolling (not
  all-at-once) restart/redeploy
  strategy for this reason, as you likely already do for other reasons.
- **Reads now FAIL CLOSED (deny-on-degrade).** A degraded or unreachable
  `rbac_store` (pool-acquire timeout, query error) now **denies** authorization
  rather than falling through to an allow — this **closes** the prior
  "corrupt `rbac.db` fails open" behavior. Watch the new
  `yuzu_server_rbac_read_degrade_total` metric and the `YuzuRbacReadDegraded`
  alert after upgrade; a degrade denies authz fleet-wide.
- **Multi-replica staleness caveat.** If you run multiple server replicas, a
  role/permission/enabled-flag change on one replica is typically visible on
  the others within a **~1 s** window under normal conditions (a durable
  generation token, refreshed at most once per second) — this is a target the
  refresh loop aims for, not a hard guarantee: a replica whose refresh is
  genuinely slow (pool saturation, a Postgres blip) can observe staleness
  beyond the window, now counted via a `stale_beyond_accepted_bound` degrade
  rather than silently assumed. A revoke is therefore not strictly
  instantaneous cross-replica — well inside the fleet's existing
  revocation-latency envelope (heartbeat + session/token TTLs measured in
  minutes), and an accepted residual risk (`LISTEN/NOTIFY` is the named
  follow-up).
- **Bounded stale-serve, then fail-fast deny, under backend degradation —
  two independent mechanisms.** An already-cached authorization decision
  keeps answering from cache for up to a **~5 s** bound past the last
  confirmed-good refresh, regardless of anything else failing (bounded
  staleness for continuity) — a brief blip does not deny cached decisions
  immediately. Separately, a fail-fast breaker governs *pool access, not
  cache validity*: once it sees **2 consecutive** pool-acquire/query
  failures, any check that is not already a cache hit denies immediately
  rather than blocking on the acquire budget first, and it stops touching
  the pool for a ~1 s cooldown between recovery probes. **"How fast" depends
  on the degradation mode:** pool exhaustion (no connection available) trips
  the breaker in well under a second (2 × the 250 ms acquire budget); a
  query blocked on a PostgreSQL-side lock (e.g. a migration touching
  `rbac_meta`) instead inherits `PgPool`'s `lock_timeout` (10 s default) per
  attempt — measured ~18.5 s for 2 such attempts against a live held lock
  (#3016). Both converge on the same fail-closed deny, just not at the same
  speed. Net effect on a sustained outage: previously-seen decisions keep
  answering for up to ~5 s regardless of breaker state; new/uncached
  decisions deny once the breaker trips, at whichever of the two speeds
  above applies; once the 5 s bound elapses, every check denies until the
  backend recovers. **Not just a sustained outage — flapping (repeated
  short degrade/recover cycles, the shape a managed-Postgres failover or a
  brief network partition actually produces) is arguably the worse case for
  this mechanism, not a milder one:** the breaker's closed-state failure
  streak resets to 0 on a single success, so each recovery — even one that
  lasts only as long as the next probe — reopens the breaker back to FULL
  concurrency rather than easing back in; a Postgres backend that is
  flapping rather than cleanly down can therefore see repeated full-
  concurrency retry bursts instead of a single clean trip-and-stay-open
  (tracked for a half-open concurrency cap, see #3016). **Blast radius while
  open is bounded by the shared connection pool, not the breaker itself:**
  every authz check on this replica denies while the breaker is open —
  including checks against securable types that have nothing to do with
  whatever degraded — because the breaker gates pool ACCESS, shared across
  every `RbacStore` caller on the process, not per-query health. **No
  operator action is needed for recovery** — the breaker self-heals: once a
  probe succeeds (the next attempt after its ~1 s cooldown), it closes
  again automatically and normal service resumes. Watch
  `yuzu_server_rbac_breaker_open` (gauge) and
  `yuzu_server_rbac_authz_check_seconds` (histogram) after upgrade. A
  companion alert, `YuzuRbacBreakerOpen` (`docs/prometheus/yuzu-alerts.yml`), is
  added in the current release, not this one: see "Behaviour change:
  service-scoped tokens, the `ITServiceOwner` ceiling on the fleet-read gate, and
  `GET /api/v1/upload-grants`" above. It fires, per replica, when the gauge stays
  at `1` for 5 minutes, and complements `YuzuRbacReadDegraded`, which is a rate
  summed across replicas by reason.
  The gauge changes only when an authorization read reports its outcome, so a
  replica that receives no authorization checks keeps its last value after the
  database recovers.
- **If you alert on the raw `generation_refresh_failed` reason label,
  re-baseline after upgrade.** This release splits what was previously a
  single reason into two: `generation_refresh_failed` (still denying —
  unchanged meaning) and the new `generation_refresh_failed_within_bound`
  (a refresh failure that landed inside the bounded ~5 s stale-serve window
  above and denied nobody). A custom alert or dashboard built against the
  pre-upgrade single-reason series may see its rate drop after upgrade —
  that is the intended effect of the split, not a sign the underlying
  condition stopped occurring. The shipped `YuzuRbacReadDegraded` alert
  already accounts for this (see `docs/prometheus/yuzu-alerts.yml`); a
  custom query built directly against `yuzu_server_rbac_read_degrade_total`
  should be reviewed against the reason list in `metrics.md` before relying
  on it post-upgrade.
- **Shutdown grace bounds now stack; raise your orchestrator's termination
  grace period, but understand what that does and does not buy you.** A
  graceful `SIGTERM` walks several independently-bounded waits — up to 30 s
  draining in-flight executions (plus any `--shutdown-drain-seconds` grace, HA WS-8, which runs
  before everything listed here and adds to it — raise your stop timeout by the same amount), up to 5 s on the gRPC shutdown deadline
  (moved up by #3495 to run earlier in the sequence, ahead of the four
  joins below and several other quick housekeeping joins not separately
  listed here, though still after the execution drain — see below),
  up to 5 s waiting on the NVD-sync background thread, up to 15 s waiting on
  the HTTP listener thread (#2703 Gate 7 item 2), and (#3261 governance
  hardening) up to 60 s waiting for WebhookStore and OffloadTargetStore to
  drain their delivery queues — the last of which runs the two stores
  CONCURRENTLY, not sequentially, so it adds 60 s to the total rather than
  120 s. Stacked, this can reach **~115 s** in the worst case if more than
  one stage is genuinely wedged; the total and each stage's own bound are
  unchanged by the reorder, only their relative sequence is. **(#3495) The policy
  evaluation, pre-flight runner, quarantine containment reconciler, and
  schedule tick background threads' gRPC dispatch calls now ride on the
  same 5 s gRPC shutdown deadline bucket above, not a separate stage** —
  `ServerImpl::stop()` now cancels in-flight gRPC RPCs before joining those
  four threads (previously it cancelled them after, so a thread genuinely
  blocked inside a gRPC stream write had no bound at
  all — not covered by the ~115 s figure, and not fixable by raising the
  grace period, since nothing in `stop()` would ever reach the cancellation
  that unblocks it). This is a strictly protective fix — no grace-period
  change is needed on upgrade, whether or not you ever hit the pre-#3495
  gap in practice; it was a real but narrow window (a stalled agent stream
  during shutdown), not a routine occurrence. **One narrower residual is NOT covered by this fix**:
  the policy-evaluation thread's join can also stall on its own Postgres
  claim call (`PolicyStore::claim_due_policies`), which isn't a gRPC
  operation and isn't bounded by `Shutdown(deadline)` — tracked separately
  (#3706), not fixed here. The shipped
  docker-compose/systemd units already set a 210 s grace period
  (`stop_grace_period` / `TimeoutStopSec`), which comfortably covers this
  residual's ordinary-contention case —
  but if you deploy under Kubernetes or another orchestrator, its default is
  frequently far shorter (Kubernetes' own default
  `terminationGracePeriodSeconds` is **30**), and a pod with slow-draining
  work in more than one of those stages can be `SIGKILL`ed mid-sequence
  before the server finishes its own bounded teardown. Raise the grace
  period to comfortably exceed ~115 s rather than relying on the platform
  default. **Two things a longer grace period does NOT fix:** (1) the 30 s
  drain window re-queries `execution_tracker_` for
  `running` executions on each of its one-second iterations — so it also
  picks up work that starts mid-drain, not just what was already running
  when `SIGTERM` arrived — but it never stops the HTTP listener from
  ACCEPTING new requests during that window, so a request that lands late in
  the drain is not bounded by the ~115 s figure at all; raising the grace
  period does not close this gap, because the gap is about admission, not
  about how long the drain itself waits. (2) if the 15 s HTTP-listener bound
  or the 60 s WebhookStore/OffloadTargetStore bound IS exceeded, the server
  force-exits (`std::_Exit(1)`) on its OWN internal schedule, independent of
  whatever grace period the orchestrator was configured with — a longer
  external grace period only prevents the orchestrator from `SIGKILL`ing
  the process BEFORE that internal bound fires; it cannot prevent or delay
  the force-exit itself, and the force-exit skips
  `offload_target_store_->flush_all()` and any other still-pending teardown
  the same way a `SIGKILL` would (this is also true of the 60 s webhook/
  offload bound itself: batched offload events flushed into the delivery
  queue immediately before the wait are abandoned, not delivered, if that
  wait times out). Note the 60 s webhook/offload bound is a heuristic sized
  against this deployment's overall shutdown budget, not a proven per-
  delivery ceiling — a slow-but-legitimate delivery target can legitimately
  push close to it under load; if you see this bound trip in production
  under otherwise-healthy conditions, that is a signal to look at your
  configured webhook/offload endpoints' latency, not necessarily a wedged
  delivery. If any of these bounds is exceeded, the diagnostic line is
  written directly to **stderr** (not through the configured logger,
  and naming which store timed out for the webhook/offload case) before the
  process force-exits. `stop()` now runs on an ordinary thread, not inside
  the SIGTERM handler (#3007), so `spdlog` would be legal here — the raw
  write stays anyway because `std::_Exit()` skips any buffered sink flush,
  and this line must reach the operator regardless. If you rely on the log
  file or a structured log sink rather than captured stderr, this one line will not
  appear there; check container/service stderr capture for it instead.
- Confirm on first boot: no `RbacStore` open/migrate errors, and that RBAC is
  enabled if you intend it to be — remember it does NOT carry over from a
  legacy `rbac.db` (Settings → RBAC, or check that confined operators see
  only their scoped fleet).

See `docs/auth-architecture.md` § "RbacStore — the authorization substrate" and
[ADR-0041](../adr/0041-rbac-store-postgres-migration.md) for the full design.

## ⚠️ Breaking: local accounts + MFA enrolments reset (AuthDB/ScimStore → Postgres, ADR-0006)

`AuthDB` (local user accounts, MFA enrolments, enrollment tokens) and
`ScimStore` (SCIM-provisioned users/groups) move from the SQLite `auth.db`
file to the server's PostgreSQL substrate in this release (ADR-0006 Wave 3),
schemas `auth` and `scim_store`. Like the earlier `ApiTokenStore` cutover,
this is a **fresh-start cutover with no data migration**: on first boot
against a Postgres database whose `auth.users` table is empty, the server
seeds exactly the config-file admin and **never reads the old `auth.db`**.
Sessions are (and always were) in-memory-only, so they are unaffected beyond
the usual "log in again after a restart."

**Who this affects:** every local-password operator, everyone with TOTP MFA
enrolled, and every SCIM-provisioned user/group. This is **not** limited to
password auth — SSO/OIDC/SAML session establishment itself is unaffected
(the IdP still asserts identity), but any RBAC role/group mapping recorded
only in the old `auth.db` local-account tables is gone until re-established.

**What happens on first PG boot:**

- Prior local accounts, roles, and MFA enrolments that existed only in the
  pre-cutover `auth.db` are gone. The server re-seeds a single admin account
  from `yuzu-server.cfg` (the same config-as-seed-only behavior as the
  original v0.12.0 AuthDB bring-up).
- SCIM-provisioned users/groups are **not** lost long-term: `ScimStore`
  self-heals on the IdP's next scheduled sync cycle, which re-provisions
  everything from the IdP as the source of truth. There is a gap between
  first PG boot and that next sync during which SCIM-provisioned users
  cannot log in.
- Anyone with TOTP MFA enrolled must **re-enrol** — the encrypted
  `mfa_totp_secret` blob and enrolment state do not carry over.
- The server logs a loud boot warning: **`AUTH DATA RESET ON POSTGRES
  CUTOVER`**. If you do not see this line on first boot against the new
  Postgres database, the cutover did not happen as expected — investigate
  before assuming accounts are intact.

**Remediate:**

1. Plan the upgrade in a maintenance window and notify every local-password
   operator, MFA-enrolled user, and SCIM administrator in advance — expect a
   batch of failed logins immediately after cutover, not a surprise incident.
2. After upgrade, log in as the re-seeded admin using the credentials in
   `yuzu-server.cfg`.
3. Re-create any other local operator accounts that are not SCIM-provisioned
   (Settings → Users), and have every user re-enrol MFA
   (Settings → Security and sign-in → Two-factor sign-in).
4. For SCIM-provisioned users, either wait for the next scheduled IdP sync or
   trigger one manually if your SCIM setup supports it; do not manually
   re-create SCIM-managed users (they will be re-provisioned).
5. Confirm the `AUTH DATA RESET ON POSTGRES CUTOVER` line appeared in the
   server log at the boot where the cutover ran.

**Not affected:** the `PgTestTemplate` config, engine principals (a separate
store), and API/MCP bearer tokens (already migrated to Postgres in an
earlier release, see "⚠️ Breaking: API and MCP bearer tokens are invalidated
on upgrade" above — this AuthDB/ScimStore cutover is independent of that one
and does not re-invalidate already-reissued tokens).

See `docs/auth-architecture.md` § "AuthDB — persistent authentication store"
for the full design rationale, and
[`docs/ops-runbooks/auth-db-recovery.md`](../ops-runbooks/auth-db-recovery.md)
for lockout/break-glass recovery — that runbook has been rewritten for this
cutover and is Postgres-native throughout (`psql "$YUZU_POSTGRES_DSN"` against
the `auth` schema).

## Notification feed moves to PostgreSQL (NotificationStore, ADR-0046)

`NotificationStore` — the dashboard toast/badge feed — moves from the SQLite
`notifications.db` file to the server's PostgreSQL substrate in this release
(ADR-0006 Wave 2, ADR-0046), schema `notification_store`. No new flag or
environment variable is added (it reuses the shared server `PgPool`).

**No legacy-SQLite migration path.** No production fleet ever ran a pre-Postgres build
of this store, so there was no real `notifications.db` data to carry over — the
one-time mandatory backfill this section originally described was retired under
ADR-0009's fresh-start-by-default amendment (see ADR-0046's Update).

These are two SEPARATE failure/detection behaviors, not one — do not conflate them:

- A reachable Postgres database whose schema can't migrate or open **is** a fatal
  startup error (fail-closed, matching every other Postgres-migrated store's
  contract): the server logs `[PG] Refusing to start` and refuses to serve at all.
- A legacy `notifications.db` file with real content **does NOT** fail startup and
  its content is **never imported** — the server opens it read-only, purely to
  count rows in `notifications` for a diagnostic warning, then boots fresh-started
  regardless of what it finds. If that table has rows, it logs a
  `NotificationStore` legacy-row-count warning at WARN; boot proceeds unaffected
  either way. There is no automated recovery path for old unread/dismissed history
  — this is display-only state (never an authorization, targeting, or enforcement
  decision), so a fresh start is acceptable in a way it would not be for an
  authoritative store.
- **Fresh installs are unaffected** — no legacy file, nothing to warn about.

**Not affected:** `/api/notifications*` request/response behavior is
unchanged — this is a storage-engine swap only, no API change.

## Audit trail on PostgreSQL — legacy `audit.db` no longer imported (AuditStore, ADR-0040)

The audit log (`AuditStore`, the SOC 2 evidence chain) runs on the server's
PostgreSQL substrate (ADR-0006 Wave 1.3, schema `audit_store`). No new flag or
environment variable is needed: the store reuses the shared `--postgres-dsn` /
`YUZU_POSTGRES_DSN` connection the rest of the server already requires, and
(like every server store) it **fails closed** at boot if Postgres is
unreachable — there is no SQLite fallback.

**No legacy-SQLite migration path.** This release retires `AuditStore`'s
one-time, mandatory, streamed backfill from a legacy `audit.db` (`#3623`,
`chore/retire-migrate-from-sqlite-auditstore`, ADR-0009's hard-cutover Update)
— no production Yuzu fleet has ever run a pre-Postgres build, and this is a
hard cutover with no migration path held open for any store, including this
one, accepting permanent audit-trail loss as the failure mode if that premise
is ever wrong for a specific host. `AuditStore` had been the
one deliberate, permanent exception to ADR-0009's fresh-start default — audit
evidence cannot be regenerated the way config or cache state can — until this
release withdrew it. These are two SEPARATE behaviors, not one — do not
conflate them:

- A reachable Postgres database whose schema can't migrate or open **is**
  still a fatal startup error (fail-closed), unchanged from before.
- A legacy `audit.db` file with real content **does NOT** fail startup and its
  content is **never imported**. Its permissions are forced to owner-only
  (`0600`, plus its `-wal`/`-shm`/`-journal` sidecars) if they aren't already —
  this file may hold plaintext secret material from a since-fixed historical
  bug, same obligation as every other legacy-file-hardening store on this page
  — POSIX only, a no-op on Windows, #3593 — then the server opens it
  read-only, purely to count rows in `audit_events` for a diagnostic warning,
  then boots regardless of what it finds. Beyond that row count, its content
  is never read, and it is never renamed, moved, or written to. Fresh installs
  are unaffected — no legacy file, nothing to warn about.

**If you see the legacy-row-count warning and the environment genuinely has
real audit history to keep, there is no automated recovery path**: the
pre-cutover trail stays exactly where it is, at its configured path (0600
now enforced on POSIX, #3593; content otherwise untouched) — and is your operator-managed
record going forward (export it, archive it, keep it under your own
retention policy; Yuzu will never import it). The generic "reapply manually"
phrasing in the boot warning fits config-shaped stores below (a webhook
subscription, a notification preference) where reapplying means re-creating
the row through the API; it does not apply here in that sense — an audit
trail is historical evidence, not something you recreate, so "reapply" for
AuditStore means export-and-archive, never re-import.

**Rollback caution.** Do not roll back to a build older than this release.
Unlike RbacStore above, this is not just a caution about a leftover legacy
file — an older binary's own (now-removed-from-current-code) backfill logic
refuses to boot **unconditionally**, with or without a legacy `audit.db`
present: seeing this database already past this migration (the marker rows
are gone, but `audit_retention_meta` itself is not — see ADR-0040's Update),
its own idempotency-marker write hits the SAME migration's CHECK constraint
(`audit_retention_meta_no_retired_backfill_markers`) and fails with a
Postgres `23514 check_violation`, table empty or not, legacy file present or
not. This is the same class of guarantee the DROP-TABLE-group stores above
get from their `undefined_table` error — a schema-level rejection, not a
live-row-count race — with one caveat: if a legacy `audit.db` is present,
the old binary's row inserts into `audit_events` still run and commit before
this final write fails, so the refusal is loud and deterministic but not
zero-data-movement the way a first-touch `undefined_table` error is. "Just
roll back the binary" is not a supported recovery path once this migration
has run, the same as every DROP-TABLE-group store above. **If AuditStore
runs as more than one replica, upgrade every replica and any
`--mfa-reset`/`--break-glass-arm` CLI image together** during a staged
rollout — a replica or one-shot CLI still on the old binary that boots after
this migration has run on the shared database will refuse to start, same as
any other rollback attempt.

**What to do:** the `YuzuAuditBackfillFailing` alert is removed with this
release. If you copied it into your own alerting config instead of
re-importing `docs/prometheus/yuzu-alerts.yml`, remove it or it fires
permanently via `absent_over_time` on a stale local copy — a CRITICAL page
that never clears, pointing at boot-log remediation steps that no longer
exist.

**Reads deny-on-degrade.** An audit-store or connection-pool failure makes
`GET /api/v1/audit*` return `503` rather than an empty `200`, so an
infrastructure blip can never be mistaken for "no audit activity."

**Not affected:** the audit event vocabulary and REST/MCP query surface are
unchanged; SIEM export recipes keep working. One deliberate behaviour change: on
a multi-replica deployment an identical-magnitude repeat clock step no longer
re-emits `yuzu_server_audit_clock_anomaly_skips_total` on every pass (only a
distinct anomaly does) — if you alerted on that counter's *cadence*, alert on a
sustained increase instead. See
[Audit Log](audit-log.md#the-retention-clock-guard).
## Management-group confinement config migrates to Postgres (ADR-0042)

The `ManagementGroupStore` — the confinement hierarchy that backs operator
scoping and the ADR-0017 `authorize_list_read` gate — moves from the SQLite
`management-groups.db` file to the server's PostgreSQL substrate in this release
(ADR-0006 Wave 2.2), schema `management_group_store`. It reuses the existing
shared connection pool, so **no new connection flag or config is required** —
the same `--postgres-dsn` / `YUZU_POSTGRES_DSN` that every other server store
uses.

**No legacy-SQLite migration path.** No production fleet ever ran a
pre-Postgres build of this store, so there was no real `management-groups.db`
data to carry over — the mandatory backfill this section originally described
was retired under ADR-0009's fresh-start-by-default amendment (see ADR-0042's
Update). These are two SEPARATE behaviors, not one:

- A reachable Postgres database whose schema can't migrate or open **is**
  still a fatal startup error (fail-closed), unchanged from before.
- A legacy `management-groups.db` file with real content **does NOT** fail
  startup and its content is **never imported** — the server opens it
  read-only, purely to count rows in `management_groups`,
  `management_group_members`, and `management_group_roles` for a diagnostic
  warning, then boots regardless of what it finds (an empty confinement
  hierarchy, same as a fresh install). The over-deep/cyclic-tree refusal this
  section used to describe has no remaining trigger — the write path's
  depth-5 cap is now the sole guard, since nothing backfills a legacy tree
  past it anymore.

**If you see the legacy-row-count warning and the environment genuinely has
real management groups to keep, there is no automated recovery path**:
re-author the equivalent groups/memberships/role assignments against the new
Postgres-backed store via the REST API.

**Rollback caution:** see the InventoryStore section's "Rollback caution" note above — the
same unconditional rollback-refusal applies to this store (its own dropped marker table).

**Operator-visible behaviour change (fail-closed reads).** After cutover, a
confinement-feeding read that degrades (store not open, pool-acquire timeout, or
query error) now returns a distinguishable failure that the caller resolves to
**DenyAll** — a scoped operator sees a reduced or empty list rather than the
store silently returning an empty deny-set and **under-restricting** (the old
fail-open hazard). A re-parent (`PUT /api/v1/management-groups/{id}`) whose
hierarchy reads degrade now returns **503** rather than a misleading success.
Watch the new `yuzu_server_mgmt_group_read_degrade_total{reason}` counter — a
non-zero rate means scoped operators are seeing reduced/empty lists because the
confinement substrate is degraded, **not** that groups actually shrank (see
`docs/user-manual/metrics.md` § "Management group metrics" and the shipped
`YuzuMgmtGroupReadDegraded` alert).

**Not affected:** the confinement hierarchy's semantics, the REST/MCP surface,
and dynamic-group scope expressions are unchanged — only the storage substrate
and the fail-closed read posture change.

## Custom properties migrate to Postgres (ADR-0045)

The `CustomPropertiesStore` — operator-authored per-agent metadata (properties
and their optional type/validation schemas) used in scope expressions via
`props.<key>` — moves from the SQLite `custom-properties.db` file to the
server's PostgreSQL substrate in this release (ADR-0006 Wave 2), schema
`custom_properties_store`. It reuses the existing shared connection pool —
**no new connection flag or config is required**.

**No legacy-SQLite migration path.** No production fleet ever ran a pre-Postgres build
of this store, so there was no real `custom-properties.db` data to carry over — the
one-time mandatory backfill this section originally described was retired under
ADR-0009's fresh-start-by-default amendment (see ADR-0045's Update).

These are two SEPARATE failure/detection behaviors, not one — do not conflate them:

- A reachable Postgres database whose schema can't migrate or open **is** a fatal
  startup error (fail-closed), same as every other born-on-Postgres store.
- A legacy `custom-properties.db` file with real content **does NOT** fail startup
  and its content is **never imported** — the server opens it read-only, purely to
  count rows across `custom_properties`/`custom_property_schemas` for a diagnostic
  warning, then boots fresh-started regardless of what it finds. If either table has
  rows, it logs a `CustomPropertiesStore` legacy-row-count warning at WARN; boot
  proceeds unaffected either way. If you see this warning and the environment
  genuinely has real properties/schemas to keep, there is no automated recovery
  path: re-author the equivalent properties/schemas against the new Postgres-backed
  store via `PUT /api/agents/:id/properties/:key` / `POST /api/property-schemas`
  before relying on it.
- **Fresh installs are unaffected** — no legacy file, nothing to warn about.

**Operator-visible behaviour change (fail-closed reads).** After cutover, a
`props.<key>`-feeding read that degrades (store not open, pool-acquire
timeout, or query error) now aborts the whole scope evaluation rather than
silently resolving the property as absent — a `props.<key>`-scoped
dispatch/policy/push rule now matches **nobody** while degraded, instead of
(under a `NOT`/`!=` scope) silently matching **everybody**. `GET
/api/agents/:id/properties` now returns **503** on a degraded read rather
than an empty list. Watch the new
`yuzu_server_custom_properties_read_degrade_total{reason}` counter — a
non-zero rate means `props.<key>`-scoped rules may be silently matching
nobody, not that operators removed the properties (see `docs/user-manual/
metrics.md` and the shipped `YuzuCustomPropertiesReadDegraded` alert).

**Operator-visible behaviour change (fail-closed writes, 2026-08-14 follow-up).**
`PUT /api/agents/:id/properties/:key` and `POST /api/property-schemas` now return
**503** (instead of `400`) when the failure is a genuine database/store outage rather
than caller-input or schema-validation error — previously every failure from either
write, including a transient Postgres blip, surfaced as the same `400` a caller could
not distinguish from their own bad input. A caller that branches specifically on `400`
to mean "don't retry" should treat the new `503`s the same as any other transient
server error (retry with backoff); a caller that already treats any `5xx` as retryable
is unaffected. See `docs/user-manual/rest-api.md`'s per-route notes for the exact
response shapes.

**Not affected:** the `props.<key>` scope-DSL syntax and property/schema semantics are
unchanged; the `GET`/`DELETE` property routes and `GET` schema route keep their prior
response shapes — only the two write routes' failure-mode status codes changed, as
described above.

## Network-discovered device data migrates to Postgres (DiscoveryStore, ADR-0044)

The `DiscoveryStore` — the network-discovered devices behind `POST /api/discovery/scan`
and `GET /api/discovery/results` — moves from the SQLite `discovery.db` file to the
server's PostgreSQL substrate in this release (ADR-0006 Wave 2), schema
`discovery_store`. It reuses the existing shared connection pool — no new connection
flag or config is required.

**No legacy-SQLite migration path.** No production fleet ever ran a pre-Postgres build
of this store, so there was no real `discovery.db` data to carry over — the one-time
mandatory backfill this section originally described was retired under ADR-0009's
fresh-start-by-default amendment (see ADR-0044's Update).

These are two SEPARATE failure/detection behaviors, not one — do not conflate them:

- A reachable Postgres database whose schema can't migrate or open **is** a fatal
  startup error (fail-closed), same as every other born-on-Postgres store.
- A legacy `discovery.db` file with real content **does NOT** fail startup and its
  content is **never imported** — the server opens it read-only, purely to count rows
  in `discovered_devices` for a diagnostic warning, then boots fresh-started regardless
  of what it finds. If that table has rows, it logs a `DiscoveryStore` legacy-row-count
  warning at WARN; boot proceeds unaffected either way. If you see this warning and the
  environment genuinely has real discovered-device data (particularly the operator-set
  `managed` flag) to keep, there is no automated recovery path: re-run
  `POST /api/discovery/scan` and re-apply `mark_managed` against the new Postgres-backed
  store before relying on it.
- **Fresh installs are unaffected** — no legacy file, nothing to warn about.

**Operator-visible behaviour change (fail-closed reads).** `GET /api/discovery/results`
now returns **503** on a degraded read (store not open, pool-acquire timeout, or query
error) instead of silently rendering an empty device list — previously, a local SQLite
read essentially never failed short of file corruption, so this failure mode was not
practically reachable. Watch the `yuzu_server_discovery_read_degrade_total{reason}`
counter — a non-zero rate means the discovery view is degraded, **not** that no devices
were found.

**Breaking — `POST /api/discovery/scan`'s response contract changed.** The endpoint no
longer always returns `200 {"status":"ok",...}`: the response gains a `devices_failed`
count, `status` is `"partial"` when some but not all devices in a batch persisted, and
the endpoint returns **503** when every attempted device failed to persist (previously
this was silently reported as `200`/`"ok"`, with the `discovery.scan` audit row always
saying `"success"` regardless of outcome — the audit outcome is now
`"success"`/`"partial"`/`"failure"`). A caller that asserts a bare `status == "ok"`, or
that treats any 5xx from this endpoint as a hard failure needing operator escalation,
should account for the new value and status code. Re-sending the exact same request body
is safe — `upsert_device` is idempotent per `ip_address`, so a byte-identical retry cannot
double-count or corrupt already-stored devices — but a fresh re-scan is not the same
thing: `mac_address`/`subnet` overwrite unconditionally on every upsert, so a re-scan that
fails to resolve a device's MAC this time will blank a previously known-good value rather
than simply retry the earlier failure. See the REST API reference's Network Discovery
section for the full response shapes.

## Guardian quarantine records migrate to Postgres (QuarantineStore, ADR-0047)

The `QuarantineStore` — the Guardian device-quarantine bookkeeping behind
`POST /api/v1/quarantine`, `DELETE /api/v1/quarantine/{agent_id}`, and the MCP
`quarantine_device` tool — moves from the SQLite `quarantine.db` file to the server's
PostgreSQL substrate in this release (ADR-0006 Wave 2), schema `quarantine_store`. It
reuses the existing shared connection pool — no new connection flag or config is
required.

**No legacy-SQLite migration path.** No production fleet ever ran a pre-Postgres
build of this store, so there was no real `quarantine.db` data to carry over — the
mandatory, fingerprint-verified backfill this section originally described (all of
the pre-upgrade checks, refusal conditions, and move-aside/fingerprint mechanics)
was retired under ADR-0009's fresh-start-by-default amendment (see ADR-0047's
Update). These are two SEPARATE behaviors, not one:

- A reachable Postgres database whose schema can't migrate or open **is** still a
  fatal startup error (fail-closed), unchanged from before.
- A legacy `quarantine.db` file with real content **does NOT** fail startup and its
  content is **never imported** — the server opens it read-only, purely to count
  rows in `quarantine_records` for a diagnostic warning, then boots regardless of
  what it finds.

**This is a stronger warning than it looks, and a deliberate choice despite the
stakes.** Unlike most other stores retiring their legacy-SQLite path in this same
release, a genuinely non-empty `quarantine.db` here means a device an operator
quarantined is **not** re-quarantined in the server's view after upgrade — the
server's view of containment does not include whatever the warning names, though
agent-side firewall enforcement (out of scope for this store) may still be
independently in effect. This was reopened and explicitly reconsidered for this
store given the containment stakes, not defaulted by uniformity with the rest of
this retirement batch — see ADR-0047's Update for the full reasoning. **If you see
the legacy-row-count warning and the environment genuinely has real quarantine
records to keep, there is no automated recovery path**: re-quarantine the affected
device(s) via `POST /api/v1/quarantine` after confirming which devices need it.

**Rollback caution:** see the InventoryStore section's "Rollback caution" note above — the
same unconditional rollback-refusal applies to this store (its own dropped marker table).

**Operator-visible behaviour change (fail-closed reads).** `GET /api/v1/quarantine`
can now return **503** for two DISTINCT reasons — the response body's message
distinguishes them, since only one is covered by the existing metric:

- **`"quarantine list unavailable — try again"`** — a genuine store/pool/query
  degrade (store not open, pool-acquire timeout, or query error) instead of
  silently rendering an empty quarantine list; previously, a local SQLite read
  essentially never failed short of file corruption, so this failure mode was not
  practically reachable. Watch the `yuzu_server_quarantine_read_degrade_total{reason}`
  counter — a non-zero rate means the quarantine view is degraded, **not** that no
  devices are quarantined.
- **`"authorization check unavailable — try again"`** (superseded: `GET /api/v1/quarantine`
  now makes one `Security:Read` list-gate decision per request instead of a per-record
  loop, so this second message no longer occurs; an unavailable authorization store now
  answers with the gate's own 503) — the per-record
  admit-then-filter loop that scopes the list to the caller's management groups hit
  an anomalous outcome (neither an explicit allow nor an explicit 403 deny) partway
  through, most commonly a transient engine-principal-store outage landing between
  the request's initial auth check and a later per-record scope check. The whole
  list fails closed rather than silently omitting just the affected record(s) — the
  alternative is rendering a partial list that reads as complete. **This cause does
  NOT increment `yuzu_server_quarantine_read_degrade_total`** — that counter is
  wired to the store-layer degrade above only; if you see 503s here with the
  authorization-check message and the counter isn't moving, the RBAC/engine-principal
  path is what to investigate, not the quarantine store itself.

**Verify:** after the server reports ready, `GET /api/v1/quarantine` (quarantine has
no dashboard surface — REST/MCP only) shows the expected active quarantine records —
either already-live Postgres data on a redeploy, or an empty list plus the
legacy-row-count warning above on a fresh install with a real legacy file.

**Not affected:** the agent-side quarantine firewall enforcement (WFP/nftables/pf
block-all + exceptions) is untouched by this migration — only the server-side
bookkeeping's storage substrate changes. `POST /api/v1/quarantine` and
`DELETE /api/v1/quarantine/{agent_id}`'s request/response shapes, and the MCP
`quarantine_device` tool's ticket-then-recall approval flow, are unchanged.

## Device tags migrate to Postgres (TagStore, ADR-0050)

The `TagStore` — device tags behind `GET/PUT/DELETE /api/v1/tags`, the legacy
`/api/tags*` routes, the MCP `get_tags`/`set_tag`/`delete_tag`/`search_agents_by_tag`
tools, and every `tag:<key>` scope expression — moves from the SQLite `tags.db` file
to the server's PostgreSQL substrate in this release (ADR-0006 Wave 2 batch 3),
schema `tag_store`, on the existing shared pool. Tags are **dispatch-critical**:
scope expressions decide which agents a command reaches, and service-scoped API
tokens are confined by the `service` tag — which is why the read/write failure
modes below fail closed rather than degrading silently.

**No legacy-SQLite migration path.** No production fleet ever ran a pre-Postgres build
of this store, so there was no real `tags.db` data to carry over — the one-time
mandatory backfill this section originally described was retired under ADR-0009's
fresh-start-by-default amendment (see ADR-0050's Update).

These are two SEPARATE failure/detection behaviors, not one — do not conflate them:

- A reachable Postgres database whose schema can't migrate or open **is** a fatal
  startup error (fail-closed), same as every other born-on-Postgres store.
- A legacy `tags.db` file with real content **does NOT** fail startup and its
  content is **never imported** — the server opens it read-only, purely to count
  rows in `tags` for a diagnostic warning, then boots fresh-started regardless of
  what it finds. If that table has rows, it logs a `TagStore` legacy-row-count
  warning at WARN; boot proceeds unaffected either way. If you see this warning and
  the environment genuinely has real tags to keep, there is no automated recovery
  path: re-apply the equivalent tags against the new Postgres-backed store via
  `PUT /api/v1/tags` / `set_tag` before relying on `tag:`-scoped targeting.
- **Fresh installs are unaffected** — no legacy file, nothing to warn about.

**Operator-visible behaviour changes (fail-closed reads/writes).**

- A degraded tag store now returns **503** (`retry_after_ms: 5000`) on the tag
  REST surfaces and `-32603` on the MCP tools — never an empty tag list, a false
  `deleted:false`, or a silent `200` over a failed write (the legacy
  `POST /api/tags/set` previously reported `ok` even when nothing was written).
  A caller whose error handling treats `400` as "don't retry" should treat these
  `503`s as retryable.
- A `tag:<key>`-scoped dispatch **fails the whole evaluation** on a degraded tag
  read — the operation errors rather than reaching fewer or more devices than
  the expression names. Watch `yuzu_server_tag_store_read_degrade_total{reason}`
  (alert `YuzuTagStoreReadDegraded`): while it fires, the policy evaluator is
  also silently skipping `tag:`-scoped checks (`last_check_at` stops advancing).
- Agent tag syncs are bounded: an agent reporting more than 256 tags in one
  Register has the sync refused whole (logged; the agent keeps its prior tag
  set). Realistic agents report 5–20. If an agent legitimately exceeds the
  cap, reduce what it self-reports (its `scopable_tags` come from the agent's
  own configuration/plugins) — there is no server-side override knob; treat a
  sustained refusal in the server log as an agent-configuration defect.

**Verify:** after the server reports ready, `GET /api/v1/tags?agent_id=<id>` (or
the device page) shows the expected tags (re-applied via the REST/MCP surface on a
fresh install, or already-live Postgres data on a redeploy).

## ⚠️ Behaviour change: quarantine containment now covers IPv6, and reports honestly (#3282, #3283, #3284, #3285, #3286, #3260)

Six issues close against the `quarantine` agent plugin across Windows, Linux and macOS. Every
one is the same class: an outcome reported as success when it was partial, failed, or unknown.
**Read §1 before quarantining a dual-stack Linux host — it needs operator action.**

The server-side dispatch enforcement (#881) and the MCP tool's honesty fixes (#3127) ship
separately and have their own upgrade note.

### 1. Linux containment now covers IPv6 (#3282)

The Linux leg installed its `yuzu-quarantine` chain in `iptables` only. On a dual-stack or
IPv6-capable host the device stayed fully reachable over IPv6 while reporting a clean
`status|quarantined` — containment that was not containing. The plugin now mirrors the chain into
`ip6tables`, and a failure on either family is reported (`status|quarantined_partial`), never
counted as applied.

**Action required for dual-stack fleets.** Whitelist entries are routed to the chain matching
their own family, so a **v4-only whitelist now leaves IPv6 contained**. There is no blanket
"keep existing connections alive" rule on either family — only a whitelisted address survives,
in any connection state. The agent automatically whitelists its own configured server address
(an IP literal directly, a hostname resolved to its address(es) **once, at agent startup** —
never at quarantine time, and using the endpoint's own resolver), so most fleets need no manual
action here. Prefer an IP-literal `--server` config for endpoints where containment integrity
matters most, since that removes DNS from the equation entirely. If your agents reach the
server over IPv6 through a path DNS resolution of the configured address wouldn't reproduce
(split-horizon DNS, a manually pinned route), or if the server's address changes after an agent
was last started, **add the server's address to the whitelist explicitly**. See
[Security Hardening](security-hardening.md#whitelisting-on-a-dual-stack-host-read-this-before-quarantining-one).

### 2. Reporting is more conservative again (#3283, #3285, #3286, #3260)

As with the Wave-2 argv migration before it, **nothing got more broken — the reporting got more
honest**, so expect these to fire more often after upgrading:

- **macOS**: a blocking pf ruleset that is loaded while pf itself is **disabled** now reads
  `state|degraded` (traffic is not actually blocked); a pf status read that returns nothing
  recognisable reads `state|uncertain` (#3283).
- **`quarantine.status` exits non-zero** on `degraded` and `uncertain`, and sets the ABI result
  status to `UNAVAILABLE`/`PARTIAL`. A consumer that only inspects the return code can no longer
  read an unenforced or unreadable host as a clean status (#3285).
- **Windows**: containment now sets the profile default policy rather than relying on rule
  precedence alone, and the pre-quarantine profile policy is captured **write-once** — a
  re-quarantine no longer overwrites the genuine capture with the quarantine's own
  block/block policy, which previously made release replay it and strand the host while
  reporting `status|released` (#3284).
- **Concurrent mutations are serialised** — two overlapping `quarantine`/`unquarantine`/
  `whitelist` actions on one host can no longer interleave firewall mutations (#3286).

### No migration, no schema change

Rollback is data-safe. A mixed fleet is safe: an older agent simply keeps the older, less
honest plugin reporting until it is upgraded.
## Product packs migrate to Postgres (ProductPackStore, ADR-0054)

The `ProductPackStore` — operator-installed product packs behind `POST/GET/DELETE
/api/product-packs*` — moves from the SQLite `product-packs.db` file to the server's
PostgreSQL substrate in this release (ADR-0006), schema `product_pack_store`, on the
existing shared pool.

**No legacy-SQLite migration path.** No production fleet ever ran a pre-Postgres build
of this store, so there was no real `product-packs.db` data to carry over — the
one-time mandatory backfill this section originally described was retired under
ADR-0009's fresh-start-by-default amendment (see ADR-0054's Update).

These are two SEPARATE failure/detection behaviors, not one — do not conflate them:

- A reachable Postgres database whose schema can't migrate or open **is** a fatal
  startup error (fail-closed), same as every other born-on-Postgres store.
- A legacy `product-packs.db` file with real content **does NOT** fail startup and its
  content is **never imported** — the server opens it read-only, purely to count rows
  across `product_packs`/`product_pack_items` for a diagnostic warning, then boots
  fresh-started regardless of what it finds. If either table has rows, it logs a
  `ProductPackStore` legacy-row-count warning at WARN; boot proceeds unaffected either
  way. If you see this warning and the environment genuinely has real installed packs
  to keep, there is no automated recovery path: re-install the equivalent packs
  against the new Postgres-backed store via `POST /api/product-packs` before relying
  on it.
- **Fresh installs are unaffected** — no legacy file, nothing to warn about.
- `deleted_pack_ids` (the uninstall tombstone table) and its coordination lock are
  unchanged by this retirement — they still exist and `uninstall()` still writes to
  them; whether they are now themselves vestigial (their original purpose was
  guarding against the now-retired backfill resurrecting an uninstalled pack) is a
  separate, undecided question.

**Operator-visible behaviour changes.**

- `GET /api/product-packs`, `GET /api/product-packs/{id}`, and
  `DELETE /api/product-packs/{id}` now return **HTTP 503** on a genuine database outage
  instead of a misleadingly-empty pack list or a false "not found". Watch the new
  `yuzu_server_product_pack_read_degrade_total{reason}` counter (alert
  `YuzuProductPackReadDegraded`) — while it fires, `GET /api/product-packs`/
  `GET /api/product-packs/{id}` are failing closed rather than returning a
  silently-wrong result; see `docs/user-manual/metrics.md`'s "Product pack store
  metrics" section for the `reason` label vocabulary.
- **`DELETE /api/product-packs/{id}` on a missing id now returns 404** (previously 400).
- **Breaking — the error body on a rejected `POST /api/product-packs` or
  `DELETE /api/product-packs/{id}` is now the standard A4 envelope**
  (`{"error":{"code","message","correlation_id",...}}`) instead of the previous flat
  `{"error": "<message>"}` — a client parsing the old flat shape must switch to reading
  `error.message`. A genuine database error no longer echoes raw driver text to the
  caller (logged server-side instead; see `docs/user-manual/rest-api.md`'s Product
  Packs section).
- Installing a bundle whose documents assign the same item id twice now fails the whole
  install as a **400 validation error** instead of silently discarding the duplicate
  item (a pre-migration bug, not a preserved behavior) — detected before any Postgres
  interaction, so unlike a genuine database error this is **not retryable**: the same
  bundle always fails the same way.
- No change to the `#802`/W7.4 signed-pack enforcement default, the Ed25519 signature
  verification path, or the `--allow-unsigned-packs` / `YUZU_ALLOW_UNSIGNED_PACKS`
  operator escape hatch.

**Verify:** after the server reports ready, `GET /api/product-packs` shows the expected
packs (re-installed via the REST API on a fresh install, or already-live Postgres data
on a redeploy).

## Guardian Baselines migrate to Postgres (BaselineStore, ADR-0055)

`BaselineStore` — Guardian's deployable Baseline unit (`/guardian` → Baselines,
`GET /api/v1/guaranteed-state/device-compliance`) — moves from the SQLite
`guardian-baselines.db` file to the server's PostgreSQL substrate in this release,
schema `baseline_store`, on the existing shared pool. A **Baseline** is the only
deployable unit in Guardian: what a deploy enforces across the fleet is read from
each Baseline's `deployed_snapshot`, never its live member set.

**No legacy-SQLite migration path.** No production fleet ever ran a pre-Postgres build
of this store, so there was no real `guardian-baselines.db` data to carry over — the
one-time backfill mechanism this section originally described was retired under
ADR-0009's fresh-start-by-default amendment (see ADR-0055's Update).

These are two SEPARATE failure/detection behaviors, not one — do not conflate them:

- A reachable Postgres database whose schema can't migrate or open **is** a fatal
  startup error (fail-closed, matching the ladder's "authoritative" posture for this
  store), same as every other born-on-Postgres store.
- A legacy `guardian-baselines.db` file with real content **does NOT** fail startup
  and its content is **never imported** — the server opens it read-only, purely to
  count rows across `guaranteed_state_baselines`/`guaranteed_state_baseline_rules`/
  `guaranteed_state_baseline_groups` for a diagnostic warning, then boots
  fresh-started regardless of what it finds. If any of those tables has rows, it
  logs a `BaselineStore` legacy-row-count warning at WARN; boot proceeds unaffected
  either way. If you see this warning and the environment genuinely has real
  Baselines to keep, there is no automated recovery path: re-author the equivalent
  Baselines against the new Postgres-backed store via the Guardian UI/REST API
  before relying on it.
- **Fresh installs are unaffected** — no legacy file, nothing to warn about.

**Operator-visible behaviour changes (fail-closed reads).** A degraded read on
the enforcement-feeding path (`deployed_member_rule_ids()` — the source for the
push fan-out, the heartbeat reconcile, and the per-device compliance view) now
returns a distinguishable failure that the caller resolves to an explicit
abort/503, never a silent empty/"fully compliant" enforced set. `GET
/api/v1/guaranteed-state/device-compliance` returns **503** rather than a
misleadingly-empty or false-compliant result when the underlying read degrades;
Guardian deploy/delete dashboard actions show a degraded-modal rather than
reporting success. There is no dedicated backfill-outcome metric for this store —
a schema-migration failure is boot-fatal and never serves `/metrics`, so the boot
log and `/readyz` are the channels to watch during an upgrade.

**Verify:** after the server reports ready, `/guardian` shows the expected Baselines
(re-authored via the Guardian UI/REST API on a fresh install, or already-live
Postgres data on a redeploy).

## Guardian rules, events, and DEX observations retire their legacy-SQLite path (GuaranteedStateStore, ADR-0038)

`GuaranteedStateStore` — the live agent-side policy enforcement store (`/guardian`
rule authoring, drift/remediation events, DEX observations) — no longer copies a
legacy `guaranteed-state.db` file into Postgres on first boot.

**No legacy-SQLite migration path.** No production fleet ever ran a pre-Postgres
build of this store, so there was no real `guaranteed-state.db` data to carry
over — the one-time backfill mechanism this store originally shipped was retired
under ADR-0009's fresh-start-by-default amendment (see ADR-0038's Update).

These are two SEPARATE failure/detection behaviors, not one — do not conflate them:

- A reachable Postgres database whose schema can't migrate or open **is** a fatal
  startup error (fail-closed), same as every other born-on-Postgres store.
- A legacy `guaranteed-state.db` file with real content **does NOT** fail startup
  and its content is **never imported** — the server opens it read-only, purely to
  count rows across `guaranteed_state_rules`/`guardian_meta`/
  `guardian_agent_rule_status`/`guaranteed_state_events`/`guardian_observations`
  for a diagnostic warning, then boots fresh-started regardless of what it finds.
  If any of those tables has rows, it logs a `GuaranteedStateStore`
  legacy-row-count warning at WARN; boot proceeds unaffected either way.
- **Fresh installs are unaffected** — no legacy file, nothing to warn about.

**This is a stronger warning than it looks.** Unlike most other stores retiring
their legacy-SQLite path in this same release, a genuinely non-empty
`guaranteed-state.db` here means real Guardian rules an operator authored are
silently NOT loaded — enforcement resumes from an empty rule set, not the
operator's prior policy. (Guardian Baselines carry the same consequence — see
the BaselineStore section above.) If you see the legacy-row-count warning above and the
environment genuinely has real rules to keep, there is no automated recovery
path: re-author the equivalent rules against the new Postgres-backed store via
the Guardian UI/REST API before relying on it, and confirm the expected rules
are actually present (see Verify below) rather than assuming they carried over.

**Verify:** after the server reports ready, `/guardian` shows the expected rules
(re-authored via the Guardian UI/REST API on a fresh install, or already-live
Postgres data on a redeploy) — do not rely on the absence of the legacy-row-count
warning alone as confirmation that nothing was lost.

## Compliance policy engine moves to Postgres (PolicyStore, ADR-0056)

The `PolicyStore` — compliance policy fragments/policies behind `POST/DELETE
/api/policy-fragments*`, `POST/DELETE /api/policies*`, `POST /api/policies/{id}/{enable,
disable,invalidate,evaluate,remediate}`, `GET /api/compliance*`, and every dispatched
compliance check/fix/verify — runs on the server's PostgreSQL substrate, schema
`policy_store`, on the existing shared pool. Six operator-authored tables (fragments,
policies, and their input/trigger/group associations, plus per-agent `policy_status`)
plus a new operational-only seventh table, `policy_dispatch_state`, which coordinates
fleet-wide compliance-check dispatch across replicas.

**No legacy-SQLite migration path.** No production fleet ever ran a pre-Postgres build
of this store, so there was no real `policies.db` data to carry over — the one-time
backfill mechanism this section originally described was retired shortly after this
store's Postgres migration merged, under ADR-0009's fresh-start-by-default amendment.

These are two SEPARATE failure/detection behaviors, not one — do not conflate them:

- A reachable Postgres database whose schema can't migrate or open **is** a fatal
  startup error (fail-closed, matching the ladder's "authoritative" posture for this
  store), same as every other born-on-Postgres store.
- A legacy `policies.db` file with real content **does NOT** fail startup and its
  content is **never imported** — the server opens it read-only, purely to count rows
  for a diagnostic warning, then boots fresh-started regardless of what it finds. If
  either the `policies` or `policy_fragments` table has rows, it logs `A legacy
  policies.db (<path>) has <N> policy row(s) and <N> fragment row(s) but PolicyStore no
  longer backfills it...` at WARN; if the file exists but its row counts can't be read
  (corrupt, unreadable, or a locked file), it logs a similar countless warning instead.
  Either way, boot proceeds unaffected. If you see either warning and the environment
  genuinely has real compliance-policy data to keep, there is no automated recovery
  path: re-author the equivalent fragments and policies against the new Postgres-backed
  store via `POST /api/policy-fragments` and `POST /api/policies` before relying on it.

**Operator-visible behaviour changes (fail-closed reads/writes).**

- A genuine store degrade on any of the six policy/fragment mutator routes, `/evaluate`,
  or `/remediate` now returns **503** (`{"error":{"code":503,"message":...}}`) instead
  of collapsing into the same `400`/`500` a validation error or business rejection gets
  — the earlier behaviour leaked the internal error string into the response body and
  gave callers no way to distinguish "retry" from "don't retry."
- Compliance-check dispatch is now a durable, fleet-wide single-sweeper claim
  (`pg_try_advisory_xact_lock`) rather than each replica's own in-memory timer — a
  persistently-failing claim (compliance checks silently stop running fleet-wide) now
  logs at `error` and increments `yuzu_server_policy_eval_errors_total{phase="claim"}`,
  where it previously only warned with no counter.
- `POST /api/policies/{id}/remediate` now rejects (409) a second call for the same
  policy while a remediation it already started is still in flight — same-process
  dedup only; a cross-replica race is a documented, tracked gap, not yet closed.
- The compliance dashboard's hero no longer claims a "Last evaluated: just now"
  freshness that the server was not actually tracking — no dashboard regression, since
  no timestamp was ever computed; the freshness claim itself has simply been removed
  rather than shipped false. A real evaluation-health signal is tracked as a follow-up.

**Verify:** after the server reports ready, `GET /api/compliance` returns the expected
policies and fleet compliance percentage.

## Runtime configuration migrates to Postgres — OIDC client secret now encrypted at rest, config resets on cutover (RuntimeConfigStore, ADR-0060)

`RuntimeConfigStore` — the Settings-configurable overrides behind `GET`/`PUT
/api/config/:key` (retention windows, `log_level`, DEX alert-routing knobs, and the
`oidc_*` OIDC parameters) — moves from the SQLite `runtime-config.db` file to the
server's PostgreSQL substrate in this release, schema `runtime_config_store`.
`WebhookStore` and `InstructionStore` have both since merged; `OffloadTargetStore` is
now the only server store remaining on the Postgres migration ladder.

**Before you upgrade, if you use OIDC/SSO configured through Settings (not
`--oidc-client-secret`/the environment): record your IdP client secret now.** Yuzu
cannot recover it for you — `GET /api/config` never returns a secret's real value — and
this cutover does not carry it forward (see below). Without it on hand, restoring SSO
after this upgrade means generating a new client secret with your identity provider.

- **Your stored overrides do NOT carry over on this cutover.** Per ADR-0009's
  fresh-start-by-default amendment, the legacy `runtime-config.db` is never copied — no
  production fleet has ever run a pre-Postgres Yuzu build, so the mandate to preserve
  real operator config across the cutover has nothing real to preserve for this
  migration. If your `runtime-config.db` DID hold real overrides, the server checks for
  this at boot and logs a warning naming the exact count found (e.g. "legacy
  runtime-config.db holds 2 override(s) that will NOT be carried over"). **This check
  only ever inspects the legacy SQLite file — it has no way to know whether you have
  already reapplied the warned-about overrides, so it repeats on every boot for as
  long as that file still holds rows, not just the first one after cutover.** Reapply
  your overrides via Settings once, then either delete the legacy file (see below) or
  ignore the repeated warning — it is expected until you do. Every key starts at its
  CLI/env default until you do.
- **This does NOT affect OIDC configured via `--oidc-client-secret`/the environment.**
  Only Settings-configured values are reset; a secret supplied at the process level is
  read at every boot regardless of this store and is untouched by this migration.
- **`oidc_client_secret` is now encrypted at rest** (SecretCodec envelope, AES-256-GCM)
  instead of plaintext, from the point you reapply it onward.
- **The legacy `runtime-config.db`'s CONTENT is left in place, and may still contain your
  old OIDC client secret in plaintext.** This release never reads its content beyond a
  boot-time row count, never moves it, never deletes it — but it DOES force the file's
  permission bits (and any `-wal`/`-shm` sidecar's) to 0600 on every boot as a defence-in-depth
  hardening step, so "untouched" applies to content only, not to permission bits. If you
  previously configured `oidc_client_secret`, delete this file (or otherwise secure it)
  after confirming you no longer need it — it is not required for the server to run, and
  leaving it in place is a plaintext-credential-on-disk exposure this migration does not close
  on your behalf.
- **`GET`/`PUT /api/config/:key` now return an honest 503** on a genuine database
  error, rather than a response indistinguishable from "nothing configured" (`GET`)
  or a `400` validation failure (`PUT`). No change to either route's success-path
  response shape.
- **Rolling back:** because the legacy `runtime-config.db`'s content is never moved or renamed
  (only its permission bits change, per above), reverting to a pre-cutover binary restores your
  pre-cutover overrides — including a plaintext OIDC client secret, if one was there — exactly
  as they were. Anything you
  set through Settings on the Postgres-backed binary lives only in Postgres and is
  lost on rollback (reapply it after rolling forward again).
- No Settings UI or dashboard-visible change beyond the one-time reset. See
  [`security-hardening.md`](security-hardening.md) for the pre-existing OIDC secret
  redaction behaviour (unchanged by this migration) and `docs/adr/0060-runtime-config-store-postgres-migration.md`
  for the full design.

## ⚠️ Behaviour change: offload targets reset on Postgres cutover (ADR-0059)

`OffloadTargetStore` — the response-offload control plane behind
`/api/v1/offload-targets` — moves from the SQLite `offload_targets.db` file to the
server's PostgreSQL substrate in this release, schema `offload_target_store`, on the
existing shared pool. Like `ResponseStore`/`AnalyticsEventStore`, this is a
**fresh-start cutover with no data migration** (ADR-0009's 2026-08-25
fresh-start-by-default amendment — no production fleet has ever run a pre-Postgres
build of this store, so there is no legacy backfill to protect), so the legacy
`offload_targets.db` is **never read** on upgrade.

**Before you upgrade, if you have offload targets configured:** the non-secret fields
(`name`, `url`, `auth_type`, `event_types`, `batch_size`, `enabled`) are recoverable via
`GET /api/v1/offload-targets` — list them now to speed up re-registration after the
cutover. Credential values themselves were never GET-recoverable even before this
migration (`auth_credential` has always been redacted from every response), so there
is nothing new to lose there — only the non-secret configuration is worth capturing.

**What happens on first PG boot:**
- The server logs a one-time `OffloadTargetStore initialized (schema
  offload_target_store) — fresh start, no legacy backfill` line.
- Every previously-configured offload target and its delivery history is gone; targets
  must be re-registered via `POST /api/v1/offload-targets` (including credentials —
  they were never durably exportable in plaintext form to begin with).
- No operator action required beyond re-registering targets.

**Also in this release:** `auth_credential` is now encrypted at rest app-side
(ADR-0010) rather than a plaintext column; `GET`/`list()` responses gain a
`has_credential` boolean alongside the already-redacted `auth_credential`. A delivery
whose target's credential fails to decrypt (KEK unavailable, a tampered/corrupted
stored blob) is skipped entirely and logged with `error=credential_unavailable` — it is
never fired unsigned. A degraded read on `GET /api/v1/offload-targets` or
`GET /api/v1/offload-targets/{id}` now returns **503**, distinguishable from a genuine
"no targets configured" (empty list) or "no such id" (404).

**Rolling back:** because the legacy `offload_targets.db` is never touched by the
Postgres-backed binary (not read, not moved, not deleted), reverting to a pre-cutover
binary restores whatever was in that file **before** the cutover, exactly as it was.
Any target registered through `POST /api/v1/offload-targets` on the Postgres-backed
binary lives only in Postgres and is lost on rollback (re-register it after rolling
forward again).

## ⚠️ Behaviour change: OTA package catalog resets on Postgres cutover (UpdateRegistry, ADR-0061)

`UpdateRegistry` — the OTA agent-update catalog behind the gRPC `CheckForUpdate`/
`DownloadUpdate` handlers and the Settings → Updates admin page — moves from the SQLite
`update_packages.db` file to the server's PostgreSQL substrate in this release, schema
`update_registry`, on the existing shared pool. Like `OffloadTargetStore`/`ResponseStore`,
this is a **fresh-start cutover with no data migration** (ADR-0009's 2026-08-25
fresh-start-by-default amendment), so the legacy `update_packages.db` is **never read for
data migration/backfill** on upgrade — the server does open it read-only once, at boot, to
count rows and warn if it finds any (see "What happens on first PG boot" below), but never
to carry any of them over.

**Before you upgrade, if you have OTA packages configured:** list them via the Settings →
Updates page first so you know what to re-upload. Package **binaries already on disk under
your configured `update_dir` are untouched** by this cutover — only the metadata row (sha256,
rollout percentage, mandatory flag) is lost — so re-uploading the same file after upgrading
reproduces the identical sha256/size.

**What happens on first PG boot (OTA is on by default — see the note below if you've passed
`--no-ota`):**
- The server logs a one-time `UpdateRegistry initialized (schema update_registry) — fresh
  start, no legacy backfill` line.
- Every previously-configured package's metadata is gone; agents see "no update available"
  until packages are re-uploaded via `POST /api/settings/updates/upload`.
- No operator action required beyond re-uploading packages.

**Also in this release:** construction is now fail-closed for OTA (on by default; disable with
`--no-ota`, not an opt-in flag) — a reachable database whose `update_registry` schema fails to
migrate/open now refuses to start the server, rather than silently serving with OTA dead (the
pre-migration code had no such check). `ca_store`/`scim_store`'s own fail-closed construction
is already unconditional on every deployment (only their probe checks are gated, on whether
you're using default certs / have SCIM enabled) — `UpdateRegistry` is simply the first of the
three where that same construction-time posture applies with **no opt-out flag set by
default**. Plan accordingly if you're upgrading a fleet you haven't audited for Postgres
reachability — this now affects the ordinary default deployment, not an opt-in minority. `UpdateRegistry` now appears in `/readyz`'s check list and in
`/health`'s `stores` object (previously absent from both). On `/readyz`, a deployment running
with `--no-ota` sees no change — the check is vacuously true and never enters the failed list. On
`/health`/`/api/health`, a new `stores.update_registry: "ok"`/`"error"` key appears in the JSON
body for **every** deployment, `--no-ota` or not.

**Rolling back:** because the legacy `update_packages.db` is never written by the
Postgres-backed binary (opened read-only at most once, at boot, for the row-count warning
above — never moved, never deleted, never modified), reverting to a pre-cutover binary
restores whatever was in that file **before** the cutover, exactly as it was. Any package
uploaded through the Postgres-backed binary lives only in Postgres and is lost on rollback
(re-upload it after rolling forward again) — but its binary on disk under `update_dir`
survives regardless, since the cutover never touches that directory.

## ⚠️ Behaviour change: quarantine is now enforced at instruction dispatch (#881, #3127)

Quarantine previously isolated a device's network without stopping the control plane from
sending it commands. This release closes that, and separately removes two paths on which the
MCP `quarantine_device` tool claimed an isolation it had not achieved. Read this before
upgrading a deployment that quarantines devices — the alert-rule item needs operator action.

The agent-side plugin containment fixes (IPv6 coverage, and honest reporting on all three
platforms) ship separately and have their own upgrade note.

### A quarantined device is now refused at dispatch (#881)

Quarantine previously isolated a device's network without stopping the control plane from
sending it commands: the feature was enforced at the endpoint and nowhere else. Instruction
dispatch now consults containment state at the server's single dispatch chokepoint, and a
quarantined device is dropped from **every** targeting arm — by id, by scope, by management
group, and by broadcast — before the command reaches the agent.

- Denials increment `yuzu_server_dispatch_target_rejected_total{reason="quarantined"}` and write
  a `quarantine.dispatch_denied` audit row (`result=denied`).
- **The quarantine plugin's own four actions are exempt** — `quarantine`, `unquarantine`,
  `status`, `whitelist` — so release stays reachable on a contained host. The exemption is keyed
  on the action, not the plugin, so a future fifth action arrives gated rather than inheriting the
  bypass.
- **Three server-internal pushes are also exempt** — `tar.fleet_snapshot`, `__guard__.push_rules`
  and `asset_tags.sync`. These are the server keeping its own state coherent, not operator
  dispatch, and gating the Guardian push would stop a contained device receiving the enforcement
  rules that make containment meaningful. If your threat model treats quarantine as a total
  boundary, note that it is not: those three channels stay open. They are a closed set in code and
  are counted by `yuzu_server_system_reserved_push_total{capability,result}` — counted, not
  per-event audited: there is no row tying a particular push to a particular contained
  device, so this is a fleet-level signal rather than per-device evidence. Nothing outside that
  set and the plugin's own four actions reaches a quarantined device.
- **Operator-visible:** automation that dispatched to quarantined devices and appeared to succeed
  will now receive denials. That is the correction, not a regression — those commands were never
  going to be safe to run on a device you had isolated.

**Fail-closed under a degraded store.** If containment state cannot be read, the server serves a
last-known-good snapshot for up to **60 seconds**; past that, or when the store is durably
unavailable, dispatch **fails closed and refuses every target fleet-wide** rather than guess who
is contained. A background refresher re-reads containment state every 20 seconds, so the snapshot
is warm even on a server with no operator traffic — without it the budget would only have
absorbed anything on a busy server, which is not when you need it.

**The snapshot window cuts both ways, and the other direction is the quieter one.** While a
stale snapshot is being served, a device quarantined *after* that snapshot was taken is absent
from it — so dispatch to that device is **permitted**, and audited as an ordinary success. For
up to the snapshot's remaining budget, containment does not hold for a freshly-quarantined
device. The refresher bounds that window to roughly the refresh interval in the common case, and
`YuzuQuarantineGateServingStaleState` alerts on it; if you quarantine a device while
`yuzu_server_quarantine_read_degrade_total` is non-zero, confirm with `quarantine.status`
rather than assuming the dispatch gate is already holding.

**There is no operator override.** The 60-second budget is a fixed bound, not a tunable, and
there is no flag to disable enforcement — a knob that let an operator turn the gate off under
pressure would be the first thing reached for during exactly the incident it exists for. What
survives a store outage regardless: the quarantine plugin's own four actions (they never read the
store), and the three server-internal pushes below. So containment, release and whitelist repair
all remain possible while the store is down; what stops is other operator dispatch. Alert on `yuzu_server_quarantine_gate_total{outcome="fail_closed"}` — it means
instruction dispatch has stopped, and it is an outage signal rather than a quarantine one. All four `outcome` values are pre-seeded at boot, so a **zero is a measurement** rather than an absent series — you can alert on `fail_closed` before it has ever fired. Absence of the family then means the server is not exporting it at all (an older build, or a scrape that is failing), not that the gate is idle: a booted server publishes all four from boot whether or not any dispatch has happened yet.

**Alert-rule change (action may be required).** `YuzuDispatchTargetRejected` now excludes
`reason="quarantined"`. Without that exclusion, correct enforcement fires the alert: any looping
automation against one contained host clears its `>3/15m` threshold, and a fail-closed episode
increments by the whole fleet at once. If you maintain a fork of `docs/prometheus/yuzu-alerts.yml`,
apply the same exclusion — otherwise the rule gets silenced and the genuine #2500 near-miss signal
goes with it.

### MCP `quarantine_device` no longer reports phantom isolation (#3127)

Two independent bugs made the tool claim containment it had not achieved. Both are fixed, and
both are **wire-visible to an MCP client**:

- `agents_reached=0` (the agent was offline) or a dispatch that threw previously returned a
  success envelope. It now answers `-32603` — *"quarantine recorded but isolation was not
  confirmed"* — with `retry_after_ms: 5000` on a first failure. A **repeat** failure against a device that already
  has a record backs off to `60000`: the device is offline rather than busy, and (**at the time
  #3127 shipped**) nothing changed until an operator re-issued the call once the device
  reconnected — a device quarantined while offline was contained at the control plane
  (dispatch to it was refused) but **not** at its own firewall until a quarantine dispatch
  actually reached it. **#3425 closed that gap**: `QuarantineContainmentReconciler` now
  re-applies the stored whitelist automatically on reconnect (heartbeat-triggered, with a
  periodic tick backstop), so a manual re-issue is no longer required — it remains
  harmless if issued anyway. **The record still persists**; retry the same call to
  re-drive dispatch if you prefer not to wait for the automatic reconciler.
- An **already-quarantined** device was a terminal error. It is now a retryable re-dispatch
  against the **stored** `reason`/`whitelist`, not the retry's own arguments — a retry cannot
  silently rewrite a contained device's allow-list with no store update and no audit trail.

`dispatch_confirmed:true` means the plugin registry **accepted the frame**, never that the device
is provably isolated (for a gateway-attached agent the frame is only queued). Confirming
containment still requires a follow-up `status` read returning `state|active`.

**Note the REST twin has diverged on one case.** `POST /api/v1/quarantine` records only — it has
never dispatched — so it still answers `400` on an already-quarantined device: there is nothing
for it to re-drive. The `400`-vs-`503` split is otherwise unchanged.

### No migration, no schema change

Rollback is data-safe. A mixed fleet is safe: the dispatch gate is server-side and applies
regardless of agent version.

## ⚠️ Behaviour change: raw dispatch now enforces InstructionDefinition approval governance (#1398)

An `InstructionDefinition`'s declared `approval.mode` (`role-gated`/`always`) was previously
enforced only on the governed `POST /api/instructions/:id/execute` path — raw dispatch
(`POST /api/command`, MCP `execute_instruction`/`execute_bundle`/`quarantine_device`, the
dashboard, workflow, schedules, and `/auto` Deploy) never resolved a definition, so a caller who
held plain RBAC permission on an action could bypass its declared review requirement entirely by
dispatching directly instead of through the governed path. This release closes that at the single
shared dispatch chokepoint. **Read this before upgrading if any automation, integration, or
scripted workflow dispatches commands as a non-admin principal** — an operation that previously
succeeded may now be refused.

### What changed

Every dispatchable `plugin.action` pair now carries a compiled `ExecuteGate`
(`None`/`AdminOrApproval`/`AlwaysApproval`), derived strictest-wins from every shipped
`InstructionDefinition` targeting that pair. **42 pairs are gated** as of this release —
including every `script_exec.*` action, `filesystem.delete_lines`/`.write_content`/`.replace`,
`registry.set_value`/`.delete_key`/`.delete_value`, `interaction.*`, `network_actions.*`,
`wol.*`, `quarantine.quarantine`/`.unquarantine`/`.whitelist`, `rdp_control.set_state`,
`certificates.delete`, `storage.*`, `tags.clear`, `discovery.scan_subnet`, `chargen.chargen_start`,
`http_client.download`, `installed_apps.list_per_user`, `services.set_start_mode`,
`tar.configure`, and `content_dist.*` — the complete, authoritative list is
`tests/fixtures/1398_pair_gate_table.json` (search for `"AdminOrApproval"`/`"AlwaysApproval"`,
excluding the `server`/`server_internal`/`_server`-prefixed rows, which are server-internal and
never agent-dispatched).

A gated pair now denies a non-admin caller with no covering approval, **regardless of which
surface dispatched it**:

- **REST** (`/api/command`, and the legacy `chargen`/`procfetch` routes): `403`, naming the gate
  and pointing at the governed alternative (`{"error":{"code":403,"message":"approval required
  for <plugin>.<action> — ... dispatch it via POST /api/instructions/{id}/execute instead,
  which supports the approval workflow"}}`). Denials are audited (`command.dispatch`,
  `result=denied`, `detail=reason=approval_required`) and counted
  (`yuzu_server_dispatch_denied_total{reason="approval_required"}`).
- **MCP** (`execute_instruction` at `operator` tier — `supervised` tier already goes through the
  approval workflow): the denial is now a discriminated JSON-RPC error naming the reason
  (`error.data.reason: "approval_required"`), not the `no_agents_reached` tool result an
  offline/unreachable agent gets (CLOSED by #3687 — a `no_agents_reached` result no longer needs a
  manual check for whether a pair is gated before you trust it, aside from the same narrow
  dry-run-then-real-check TOCTOU window every pre-dispatch authorization check in this codebase
  accepts). **`approval_required` is one of six discriminated reasons, not the only one** — the
  same fix discriminates `Unclassified`/`Ambiguous`/`AnonymousOperator`/`Forbidden`/`KillSwitched`
  too, so a caller that only added handling for this release's `approval_required` change gets no
  warning that `Forbidden` (the most common denial in practice — a caller with no covering grant
  at all, not just an ungated approval gap) now arrives as the same kind of discriminated
  JSON-RPC error rather than the old `no_agents_reached`/ambiguous-success shape. **This coverage
  is no longer `execute_instruction`-only**: #3893 extended the identical pre-dispatch dry run
  (both the C8 pre-mint check and the main-handler backstop) to `execute_bundle` (a denied step
  now refuses the whole bundle call up front — previously an entirely-denied bundle returned a
  false JSON-RPC success naming the requested step count) and `quarantine_device` (a denial now
  runs before the quarantine record is written, and before dispatch, instead of mapping every
  denial reason to the same "retry" hint an offline device gets).
- **Schedules**: a schedule dispatching a gated pair now requires an approval ticket exactly like
  the interactive governed path (`ScheduleRunner` mints one and holds the occurrence until an
  admin approves it via the existing `/api/approvals` workflow) — this was already the behavior
  for schedules with their own `requires_approval` flag set; it now ALSO applies whenever the
  target pair itself is gated, independent of that flag.
- **`/auto` Deploy**: content_dist dispatches are unaffected — the deployment pipeline's own
  re-authorization, guarded state transitions, and audit trail are accepted as the equivalent
  control (`ApprovalProvenance::GovernedPipeline`), so no new ticket is required there.

### How to check your exposure before upgrading

Query the audit log for `command.dispatch` rows (or your own automation's recent activity) whose
`plugin`/`action` appears in the gated list above, dispatched by a non-admin principal. If you
find any, either grant the dispatching principal an admin role, or migrate that automation to
dispatch through the governed path (`POST /api/instructions/:id/execute`, or an MCP
`supervised`-tier token) so it goes through the approval workflow instead of raw dispatch.

### Schedule approval tickets are now bound to their reviewed content

A separate hardening in this same release: a schedule's approval ticket is now bound to the
specific `plugin`/`action` it was approved for, not just the definition's id. If a definition's
`plugin`/`action` is edited (`PUT /api/instructions/{id}`) after a schedule's ticket for it was
approved but before the schedule's next fire, the stale ticket no longer redeems — the schedule
correctly requests a fresh ticket for the new content instead of firing under review that was
never given for it. This is self-healing (no manual database intervention needed): approve the
new ticket the same way you approved the original. You would only notice this if you edit a
scheduled definition's target action between approval and fire, which is unusual but not
unsupported.

### Migration

`ApprovalManager`'s SQLite schema gains two additive columns (`target_plugin`, `target_action`,
migration v8) — no backfill, no data loss, safe on a large existing `approvals` table (constant
default, metadata-only `ALTER TABLE`). Rollback is safe: an older binary ignores the two new
columns on read and simply doesn't populate them on write, which the new binary's fail-closed
matching correctly treats as "must re-request" rather than a corruption state.

### No config flag, no override

There is no flag to disable the new gate. An admin caller, or a caller dispatching via the
governed path with a redeemed approval ticket, is not subject to it.

## Behaviour change: a `rule_id` outside the documented charset is now rejected at creation (#4665)

`POST /api/v1/guaranteed-state/rules` and MCP `create_guardian_rule` now enforce the documented
`rule_id` charset (`[A-Za-z0-9._-]+`, at most 256 bytes) at creation — a request whose `rule_id`
violates it now gets `400` (REST) or an error (MCP), audited as `guaranteed_state.rule.create`
`denied`, instead of being accepted on any non-empty string. This closes an operator-authored
log-injection exposure (#4665): log lines across the Guardian/Spark subsystem now also neutralise
a rule id or Spark key before printing it, but a `rule_id` that never conformed to the documented
shape (a space, a newline, or any other disallowed byte) could previously still be created.

**Who this affects:** almost nobody — the charset was already documented before this release, just
not enforced, so create requests generated by the dashboard, the REST/MCP tooling, or any client
following the documented contract are unaffected. This only changes behaviour for a caller that was
relying on the previously-permissive accept-anything-non-empty behaviour to create a `rule_id`
outside `[A-Za-z0-9._-]+` or longer than 256 bytes.

**What to do — this is a hard cutover, not a migration, by deliberate decision:** enforcement at
the server is create-only, so an existing rule whose `rule_id` predates this release and doesn't
conform to the charset is never torn down *by the creation check itself*. But the server-side push
builder now **excludes** any such row from every push it builds (logged at `error` with a sampled
rate limit as `Guardian push: rule ... has a rule_id that fails the .../256-byte charset check
(#4665) — excluding it from this push`, and counted in
`yuzu_guardian_push_rule_excluded_total{reason="invalid_rule_id"}`), the same way an over-depth
`spec_json` is already excluded — and the agent's `full_sync` path unconditionally tears down and
rebuilds its ENTIRE active rule set from whatever the push actually contains. Put together: **the
first `full_sync` an upgraded agent receives permanently disarms every rule with a non-conforming
`rule_id`** (logged at `warn` on the agent, matching `full_sync is disarming N rule(s) with a
rule_id outside the [A-Za-z0-9._-]+/256-byte charset (#4665) -- hard cutover, not preserved`). This
is not silent — the server-side exclusion is both logged AND metered
(`yuzu_guardian_push_rule_excluded_total`); the agent-side disarm is logged only, with no metric of
its own yet — but it IS a real, one-time loss of a previously-enforcing control if you don't act
first. Every OTHER rule in scope is unaffected either way — this only ever touches rows that were
already unenforceable by the documented contract.

**Finding a non-conforming legacy `rule_id` — do this BEFORE upgrading, not after:** `GET
/api/v1/guaranteed-state/rules` returns every rule regardless of its `rule_id`'s shape; filter the
response for any `rule_id` that doesn't match `^[A-Za-z0-9._-]{1,256}$` — that's the same predicate
the server now enforces at creation. For each one you find, either delete it (see below) and
recreate it under a conforming `rule_id`, or accept the loss consciously — there is no third option
that preserves it under its existing id.

**Removing a non-conforming `rule_id`:** the two delete surfaces have DIFFERENT restrictions, not
a simple REST-restricted/MCP-unrestricted split. REST `DELETE
/guaranteed-state/rules/{rule_id}` routes on the same charset regex the create path now enforces
(`[A-Za-z0-9._-]+`, no length bound), so it **can't** reach a `rule_id` containing a byte outside
that charset, but it has no length cap of its own and so **can** reach one that's charset-clean but
over 256 bytes (a shape only possible pre-#4665, when creation had no length bound either). MCP
`delete_guardian_rule`'s own input schema caps at `maxLength: 256` with no charset `pattern`, so it
has the exact opposite gap: it **can** reach a charset-violating id (any length up to 256), but
**can't** reach one that's charset-clean and over 256 bytes — the request is rejected by schema
validation before the handler's own logic ever runs. A `rule_id` that violates BOTH (wrong charset
AND over-length) is reachable by neither REST nor MCP; fall back to a direct database delete
(`guaranteed_state_store.guaranteed_state_rules`) for that case.

## Behaviour change: `preview_scope_targets` / `scope/preview` now resolve `from_result_set:`/`props.` atoms correctly (#4981)

`POST /api/v1/scope/preview` and MCP `preview_scope_targets` previously evaluated a scope
expression against a bespoke attribute resolver that only understood
`ostype`/`arch`/`hostname`/`agent_version`/`tag:<key>` — a `from_result_set:<id>` or
`props.<key>` atom silently resolved to unset, so the atom's comparison was always false, and
`NOT from_result_set:<id>` inverted that to match every agent the caller could see regardless
of the referenced set's real membership. Both surfaces now route through the same
fail-closed evaluation ladder a real dispatch uses.

**Who this affects:** anyone who has called either surface with an expression containing
`from_result_set:` or `props.`. If you relied on the old (incorrect) match set for either atom
kind, re-check any automation built on that response before upgrading — the direction of the
correction depends on how the atom was used: a negated `NOT from_result_set:<id>` was, in
practice, matching your whole visible fleet, and the corrected match set will generally be
narrower and more accurate to what a real dispatch of the same expression would actually
target; a plain (non-negated) `from_result_set:`/`props.<key>` atom always evaluated false under
the old resolver, so its match set was previously stuck at 0 and the corrected set will
generally be broader, now actually populated with real members.

**New error responses a strict client should handle:**
- **403 (REST only)** — a service-scoped API token calling `POST /api/v1/scope/preview` now gets
  denied outright, rather than admitted with a silently narrowed match set (closing the same
  cross-service-reach gap #4980 closed on a sibling result-set route). MCP `preview_scope_targets`
  is unaffected by this change — it already denied a service-scoped token outright before this
  release.
- **404** `RESULT_SET_NOT_FOUND` (REST) / `kInvalidParams` (MCP) — a `from_result_set:<id>`
  referencing a result set that is absent, expired, or not owned by the caller now aborts,
  instead of silently matching nothing (or, negated, everything).
- **503**, with a `retry_after_ms` hint — a degraded backend store or presence read now aborts
  instead of under- or over-reporting the match set.

A preview call no longer extends a referenced result set's TTL as a side effect — it is now a
genuine read-only dry run, matching its documented `readOnlyHint: true`.

## Upgrade Order

Always upgrade in this order:

1. **Server** -- new server versions accept connections from older agents. A server-only restart while a gateway stays connected recovers without operator action once the gateway is also at this version; see [What happens when the server restarts](gateway.md#what-happens-when-the-server-restarts) (an older gateway keeps the previous behaviour described there)
2. **Gateway** -- updated to match server protocol changes
3. **Agents** -- can be upgraded via OTA or manually, in batches

Never upgrade agents before the server -- the server must understand the agent's protocol version.

## Pre-Upgrade Checklist

Before upgrading any component:

- [ ] Back up all data (see [Server Administration](server-admin.md))
  - `yuzu-server.cfg`, `auto-approve.cfg` — enrollment tokens and pending agents are PostgreSQL-authoritative since HA WS-6 6.2 (`auth.enrollment_tokens` / `auth.pending_agents`); back them up as part of the `pg_dump` below, not as local files. A pre-6.2 install's `enrollment-tokens.cfg` / `pending-agents.cfg` are still worth including in a manual backup **taken before that upgrade** — they are the one-time import source at the first 6.2 boot (see the rolling-upgrade note below)
  - The NVD cache `nvd_cves.db` in `--data-dir` (the one remaining server SQLite store) — use `sqlite3 <path> ".backup ..."` rather than `cp` against a live database
  - The blob directories `agent-updates/` (or your `--update-dir`) and `upload-blobs/` in `--data-dir` — the database holds only the OTA-package and completed-upload records that point into them, so a restored dump without these directories leaves records with no files
  - The **PostgreSQL database** (ADR-0006 — bundled in the composes; provisioned natively by `install-server-postgres.sh`) **and the whole `--ca-dir`**, taken at the same point in time — use `pg_dump --format=custom`; see [Server Administration § PostgreSQL Substrate](server-admin.md#postgresql-substrate) for the full backup/restore procedure and the ADR-0010 restore-pairing invariant (DB and `KeyProvider` keys-dir backups restore **together**)
- [ ] **Upgrading to HA WS-6 6.2 or later, running more than one server replica?** Stop
  every pre-6.2 replica before starting the first 6.2+ one. The one-time `enrollment-tokens.cfg`
  / `pending-agents.cfg` import runs at boot on whichever replica starts first and stamps a
  content-fingerprint marker in `auth.import_meta`; a second pre-6.2 replica started afterwards
  against the same `--data-dir` files would only ever match or mismatch that already-consumed
  marker, never contribute new state — its own `.cfg` files are simply skipped or, if they differ,
  refused (never merged). A restored pre-6.2 backup with a fingerprint that no longer matches the
  live `auth.import_meta` row is likewise **refused, not merged** — look for a `CRITICAL` log line
  naming the mismatched file and the `yuzu_server_enrollment_import_total{outcome="fingerprint_mismatch"}`
  metric; see [ADR-2002 §8](../adr/2002-high-availability-architecture.md#8-pki--ca-high-availability-q8) for the marker/fingerprint mechanics.
  **A fingerprint mismatch does NOT block boot** — unlike a PG error or read failure with the file
  present (which refuses to start, the same posture as the first-boot admin seed), a mismatch is
  logged and the server starts normally with whatever enrollment state is already in Postgres; the
  stale `.cfg` file's rows are simply never imported, and the file itself is left in place under its
  original name (not renamed to `.imported`, since nothing was imported). Recover by comparing the
  stale file's rows against the current `auth.enrollment_tokens`/`auth.pending_agents` (dashboard, or
  `psql`), manually recreating anything genuinely missing (mint a new token / re-add the pending
  agent), then archiving or deleting the leftover `enrollment-tokens.cfg` / `pending-agents.cfg` once
  you've confirmed nothing in it is needed.
- [ ] **Verify the server's clock before upgrading** (`timedatectl status` or
  `chronyc tracking`; under Docker it is the host's clock that matters). Rows
  already stamped cannot be protected retroactively by any setting, and a server
  upgraded to schema v3 while its clock was skewed FORWARD could delete expired
  audit rows unremarked on its first guarded pass - see [Retention clock
  guards](#retention-clock-guards-2360-server-audit-store-2361-tar-agent-warehouse)
  below and #2579. Fixed forward: that pass now declines instead, so the risk is
  to servers upgrading FROM an affected version with a wrong clock.
- [ ] Check the [CHANGELOG](../../CHANGELOG.md) for breaking changes
- [ ] Verify disk space (at least 500 MB free for migration)
- [ ] Note current version: `yuzu-server --version` / `yuzu-agent --version`
- [ ] Plan a maintenance window (upgrades take < 5 minutes per component)
- [ ] **Review new opt-in telemetry:** this release adds DEX per-application
  performance sampling (`procperf`), a new usage-class data category. It is
  **off by default** (no action needed to keep it off) — but if you intend to
  enable it for an EU workforce, treat it as a works-council co-determination
  trigger. See the *DEX per-application sampling* upgrade note in
  [Server Administration](server-admin.md#upgrade-notes).
- [ ] **New device performance sampling on Linux:** this release wires the TAR
  `perf` collector on **Linux**, and because it is default-ON, Linux agents
  **begin recording on-device performance samples automatically on agent
  upgrade** (device-level, no user identity; opt out per host with
  `tar.configure perf_enabled=false`). These rows carry no per-user or per-app
  identity, but the project treats the *capability to observe* as the
  works-council co-determination trigger, so EU deployments should note the new
  Linux coverage as they did for the Windows network facts below.
  Per-application sampling (`procperf`) is now also implemented on Linux but
  remains **opt-in on every OS** — the works-council posture above applies
  unchanged. Details and caveats: the upgrade note in
  [the TAR user manual](tar.md#performance-impact).
- [ ] **New network telemetry on Windows:** this release makes **Windows** agents
  emit device-aggregate network facts (throughput + interval retransmit rate) on
  the heartbeat, automatically on agent upgrade — gated by the existing
  `--dex-disable` / `YUZU_AGENT_DEX_DISABLE` flag (no separate opt-in). These
  carry no per-user or per-application identity (lighter than `procperf`), but the
  project treats the *capability to observe* as the works-council co-determination
  trigger, so EU deployments should note the new Windows coverage as they did for
  the DEX signals. See [Network Quality](network.md) → Collection & privacy.
- [ ] **New daily installed-software sync (ADR-0016):** on agent upgrade, agents
  begin syncing their **machine-wide installed-software** inventory to the server
  once per ~24 h over the existing gRPC channel (hash-skip keeps unchanged hosts
  to a tiny hash, not the full list). Three operator-visible effects: (a) new daily
  outbound `ReportInventory` traffic per agent — adjust egress baselines/firewall
  expectations; (b) the data lands in a **new Postgres schema**
  (`software_inventory_store`, auto-migrated at boot, fail-closed); (c) it requires
  the `installed_apps` plugin to be loaded — a build with `-Dbuild_agent=false`
  (or a plugin dir missing it) collects **nothing**, silently (agent logs only at
  debug). Machine-scope only, no end-user PII (no username collection) — but the
  data is device-attributable, and on **personally-assigned devices** installed-
  software enumeration may be **works-council co-determination-relevant** (see the
  works-council note in [Installed-Software Inventory](inventory.md)). To suppress
  collection entirely, pass **`--inventory-disable`** / set
  `YUZU_AGENT_INVENTORY_DISABLE` on the agent (deploy-time opt-out). Reads are
  gated on the new `Inventory:Read` RBAC securable; today the data is queryable via
  direct SQL (see [Installed-Software Inventory](inventory.md)). On a **non-English
  fleet**, upgrading across #1662 changes stored names: app/publisher names that
  earlier builds mangled to `?` (cp1252) are rewritten to correct UTF-8 on each
  agent's next daily sync, so any query automation that matched the corrupted `?`
  strings will return nothing afterward — see the non-ASCII troubleshooting note in
  [Installed-Software Inventory](inventory.md) for the force-resync path.
- [ ] **`installed_apps list` rows carry two more fields (breaking for fixed-width parsers):** the operator `list`
  action now emits seven fields instead of five (`…|install_date|install_location|bundle_id`). Check any script,
  SIEM parser or export that reads `crossplatform.software.inventory` output; agents not yet upgraded keep
  emitting five and do not escape `|`, so accept a row only when it has exactly 5 or exactly 7 escape-aware
  tokens, reading the sixth/seventh only from agents known to be on plugin 1.2.0+. See
  [Server Administration](server-admin.md#upgrade-notes).
- [ ] **New SparkEngine health telemetry (auto-on, engine-health only):** on agent
  upgrade, agents begin shipping SparkEngine posture tags on the existing
  heartbeat (2 keys when quiescent), and the server exposes 11 new
  `yuzu_fleet_spark_*` gauges. The engine is **observe-only at this rung** —
  nothing about Guard detection or enforcement changes — and the tags are pure
  engine-health counts (no user, process, or path identity; no works-council
  trigger). During a staged rollout, not-yet-upgraded agents are simply absent
  from the new gauges — expected, see the staged-rollout example in
  [Metrics](metrics.md#sparkengine-fleet-gauges). Deploy-time opt-out:
  `--spark-disable` / `YUZU_AGENT_SPARK_DISABLE` (the opt-out itself stays
  visible as `yuzu_fleet_spark_disabled`). See
  [Guaranteed State](guaranteed-state.md#sparkengine--the-next-generation-detection-engine-observe-only).
- [ ] **New Guardian claim-lifecycle health telemetry (auto-on, sparse; dormant in steady state until the Spark path is enabled, #5403, #5404, #4472):** on
  agent upgrade, agents gain 15 new `yuzu.guardian_*` heartbeat tags (13 sparse count tags and 2 pending-age tags), and the server exposes the matching
  `yuzu_fleet_guardian_*` gauges (13 fleet sums and 2 fleet maxima, the latter ending `_max`).
  - **Steady state.** No agent enables the Spark path today, so on an inert fleet every one of these is **absent in steady state**
    (`yuzu.guardian_ack_maint_exceptions` is the one that can appear on an inert fleet: its push-apply source runs whether or not the Spark
    path is enabled, and ships only if that step throws); an absent gauge means nothing to report, never a measured `0`. Nothing about
    Guard detection or enforcement changes, and the tags carry no user, process or path identity. No alert rule ships with them.
  - **Mixed versions.** A not-yet-upgraded agent omits the tags, so the absence of a gauge from an old agent reads as healthy even when it
    is not; upgrade the **server first** so the gauges exist when the first upgraded agent reports (an older server stores the unknown tags
    and ignores them).
  - **At the Spark flip (not part of this upgrade), upgraded agents.** They hold the policy generation and keep being re-pushed while a
    wedged rule or a compensating teardown is outstanding (each re-push writes a `guaranteed_state.reconcile` audit row, about once per
    heartbeat per held agent; the agent suppresses the identical re-pushes and applies one in full about every 330 s; if a rule of the hung call's mechanism type that the push changes, or that is not healthy, is in the push, every re-push after the first of those is applied in full (a healthy, unchanged rule is skipped since #4415); see the Same-type condition in the wedged-rule hold note of [Guaranteed State](guaranteed-state.md#sparkengine--the-next-generation-detection-engine-observe-only)).
  - **At the Spark flip, agents without the #5459 retry suppression.** Every agent built from PR #4529 up to the #5459 change carries the
    earlier three-re-apply waiver; builds from before PR #4529 (release 0.13.0 and earlier) have no waiver and no acknowledgment ledger at all.
    Such an agent can acknowledge the generation after three re-applies of a wedged rule (and, without the
    #4472 fix, while a compensating teardown is outstanding), which can leave the rule unarmed under an acknowledged generation if the hung
    arm later fails (see the wedged-rule hold note in Guaranteed State).
  - **Telling the two kinds of build apart.** The base version number alone does not separate them: release 0.14.0 and its release
    candidates, any 0.14.x hotfix cut from them, and dev or main builds from after PR #4529 and before the change all carry the waiver, and dev and main
    builds report the base version set in `meson.build` (`0.14.0` when this entry was written) before and after the change. `yuzu-agent --version` and the agent's start-up log print the full version (`<version>+<build number>`)
    and the short commit hash, and the `yuzu.agent_version` heartbeat tag carries the same full version; a build from source carries the
    change only if its commit contains the #5459 change. The build number and commit hash are read
    from git when the build is configured, so a build from source that was not re-configured after
    pulling can report a stale commit hash. For a release build, use the release notes, which name the first release that
    carries the #5459 change. The build number is `git rev-list --count HEAD` at configure time and the release workflow's checkouts do not
    set a fetch depth, so a release artifact's `+<build number>` may not be a true commit count: compare build numbers only between builds
    from the same checkout depth, and identify a release build by its release notes and commit hash.
  - See [Guaranteed State](guaranteed-state.md#sparkengine--the-next-generation-detection-engine-observe-only) and
    [Metrics](metrics.md#guardian-m1-health-stream-fleet-gauges).
- [ ] **Changed agent signal handling (Linux/macOS):** graceful shutdown now runs
  on a dedicated watcher thread (fixes an abort/hang class on `SIGTERM`), and a
  **second** `SIGTERM`/`SIGINT` immediately hard-exits the agent (exit 1) —
  by design, with **no grace window**: the second signal is read as "the stop is
  wedged". Stop scripts that deliberately double-signal agents will now
  force-kill them; send one signal and wait instead. On Windows a second Ctrl-C
  also terminates promptly. See *Stopping a wedged agent* in
  [Server Administration](server-admin.md).
- [ ] **New agent shutdown watchdog (#2233 item 3, "S+"):** on upgrade, both
  `AgentImpl::stop()` and the agent's own `run()`-exit teardown arm a 20-second
  internal deadline; if guardian/spark/DEX teardown or any other blocking step
  hasn't returned within it, the agent self-terminates (`hard_exit`, **exit
  code 4** — new, distinct from the existing codes 1 and 3 above) instead of
  hanging indefinitely. You do not need to send a second signal to recover from
  this class of wedge — sending one just makes the exit happen sooner (code 1)
  instead of after the 20s deadline (code 4); which code is actually reported
  is a race if both happen for the same wedge, so treat it as a hint, not a
  certain diagnosis. On Windows, `sc stop`/service shutdown is now also bounded
  by the same 20s watchdog; the agent's `--install-service` recovery-actions
  configuration (#1822) auto-restarts on a watchdog fire similarly to the
  Linux `Restart=always` unit, but the exit shows up as a generic unexpected
  termination rather than one of the SCM's own "specific error" buckets.
  During shutdown the agent now waits about 1 second per statement step (5 in normal
  operation) for a `kv_store.db` that another process holds locked (#5604). SQLite's
  own internal retries (for example on the WAL index) are not covered by that cap and
  were measured at up to about 2.3 seconds against a 1 second budget on Linux (phasing
  dependent), on every platform. A locked `kv_store.db` no longer pushes the
  stage-by-stage shutdown past the deadline in the cases measured (6.03 s largest; see
  the limits in [Guaranteed State](guaranteed-state.md)); a shutdown-time write to
  that store can fail where the longer wait would have succeeded. Live in every agent,
  that can leave the legacy-sink loss counters showing their previous value after the
  restart, and can lose a plugin's last shutdown-time storage write or a sync
  scheduler or license scan write made at shutdown. Once Spark detection is enabled it
  can also cost one Guardian baseline recapture at the next start (a file that drifted
  between the lost capture and that start is accepted as the baseline) and lose
  pending lifecycle-journal records; see the baseline note in [Guaranteed
  State](guaranteed-state.md) and, after an exit 4, *Stopping a wedged agent* in
  [Server Administration](server-admin.md).
  `AgentImpl::stop()` and the run()-exit teardown each arm this deadline
  separately, and in the worst case the two can compose sequentially to as
  much as ~40s before either one fires, past the 30s SCM hint — but that
  specific case is a slow clean stop, not a hang or a restart (a clean
  `SERVICE_STOPPED` report doesn't trigger the recovery actions above
  either). See *Stopping a wedged agent* in
  [Server Administration](server-admin.md).
- [ ] **Agent logging is now asynchronous, with a new self-exit code 5 (#4666
  PR-2):** on upgrade, the agent stops writing log lines synchronously on the
  thread that produced them and instead hands them off to a dedicated
  logging worker thread over a fixed-size, pre-allocated 8192-slot queue
  (3.34 MB of RSS, paid regardless of how much is actually logged). Under
  sustained overload the queue drops the oldest still-queued lines
  (`overrun_oldest`) rather than blocking or growing; there is no
  `--log-sync` opt-out. Not a breaking change: same log format, same
  `--log-file`/rotation behaviour, no new flags, with one exception: the
  "Received signal, shutting down..." line on `SIGINT`/`SIGTERM`/Ctrl-C used
  to be a raw stderr-only write and now goes through the same configured
  logger as everything else, so it also lands in `--log-file` and picks up
  JSON formatting under `--log-format json` — and, since it's now an
  ordinary `info`-level line rather than an unconditional raw write, it is
  silently **absent entirely** at `--log-level warn` or above (previously it
  always printed regardless of level). The other new operator-visible
  surface is a fifth self-exit code: tearing down the async logger during
  shutdown either times out on a 2-second internal watchdog or fails
  outright, and either cause self-terminates with **exit code 5**, distinct
  from the existing 1, 3, and 4. A supervisor script or alert keyed to a
  fixed exit-code set should widen it to include 5. See *Stopping a wedged
  agent* in [Server Administration](server-admin.md).
- [ ] **Changed server signal handling (Linux/macOS, #3007):** the identical fix
  as above, now applied to the server — graceful shutdown runs on a dedicated
  watcher thread (fixes the same abort/hang class on `SIGTERM`, previously
  reproducible as a debug-build `SIGABRT` from a deadlock detector), and a
  **second** `SIGTERM`/`SIGINT` immediately hard-exits the server (exit 1) with
  **no grace window**. Also new: a `SIGTERM`/`SIGINT` arriving before the server
  finishes starting up now exits promptly with code 1, instead of being
  silently ignored — a boot-time signal genuinely cannot be handled gracefully,
  so this is a fail-visible improvement, but it means a very-early stop attempt
  during a fast redeploy or a mistuned `livenessProbe.initialDelaySeconds`
  (a failing *readiness* probe only pulls a pod from Service endpoints — it
  never sends a stop signal; a failing *liveness* probe is what triggers a
  kill-and-restart) will now observably exit rather than continue booting.
  Stop scripts that
  deliberately double-signal the server will now force-kill it; send one
  signal and wait instead. See *Stopping a wedged server* in
  [Server Administration](server-admin.md).
- **Non-English fleets — additional plugins (#1682).** The same `Reg*A` → `Reg*W`
  encoding fix was extended to four more Windows plugins: `vuln_scan` (app
  DisplayName/Publisher/Version in vulnerability findings), `os_info` (OS
  ProductName / edition), `sccm` (client version), and `windows_updates` (the WSUS
  `WUServer` URL). Unlike `installed_apps`, these produce **transient** response
  data — no stored names are rewritten; each call simply delivers correct UTF-8
  immediately after the agent upgrade. Any operator automation that matched
  previously-mangled non-ASCII strings in those plugins' responses (e.g. a vuln
  finding filtered on `title == "Caf?"`) will need updating.

## Upgrading the Server

### Linux (systemd)

```bash
# 1. Stop the server
sudo systemctl stop yuzu-server

# 2. Back up data
sudo cp /var/lib/yuzu/*.db /var/lib/yuzu/backup/
sudo cp /etc/yuzu/*.cfg /var/lib/yuzu/backup/
# ... and the Postgres database, if provisioned. The DSN lives only in the
# root-only env file (NOT in interactive shells) — load it, and keep the
# password off the argv via PGPASSWORD. Full recipe + restore procedure:
# server-admin.md § PostgreSQL Substrate.
sudo sh -c '. /etc/yuzu/yuzu-server.env
  export PGPASSWORD="$(printf "%s\n" "$YUZU_POSTGRES_DSN" | sed -E "s!^[a-z]+://[^:/@]*:([^@]*)@.*\$!\1!")"
  pg_dump --format=custom --file=/var/lib/yuzu/backup/yuzu-pg.dump \
    "$(printf "%s\n" "$YUZU_POSTGRES_DSN" | sed -E "s!^([a-z]+://[^:/@]*):[^@]*@!\1@!")"'

# 3. Replace the binary
sudo cp yuzu-server /usr/local/bin/yuzu-server
sudo chmod +x /usr/local/bin/yuzu-server

# 4. Start the server (schema migrations run automatically)
sudo systemctl start yuzu-server

# 5. Verify
sudo systemctl status yuzu-server
curl -s http://localhost:8080/livez
```

### Docker

The reference deployment template lives at `deploy/docker/docker-compose.reference.yml` — copy it into your deployment directory next to a `.env` file, set `YUZU_VERSION`, and harden per the inline TLS checklist in the file header **before** exposing the stack to any untrusted network. The compose file declares two named volumes for the server that survive container replacement: `server-data` holds the remaining mutable state kept on disk — `yuzu-server.cfg`, `auto-approve.cfg`, the NVD cache SQLite database, and OTA binaries; `certs` holds `/etc/yuzu/certs`, the internal CA and the secrets KEK files that the Postgres data (on `postgres-data`) depends on. Enrollment tokens and pending agents are PostgreSQL-authoritative (HA WS-6 6.2, `auth.enrollment_tokens` / `auth.pending_agents`) — a pre-6.2 volume's `enrollment-tokens.cfg` / `pending-agents.cfg` are imported once, automatically, at the first 6.2+ container's boot, then renamed to `<name>.cfg.imported`.

An upgrade is a pull-and-restart:

```bash
# 1. Back up first (see below) — the old data is the only recovery path
#    if a migration fails on your specific DB.

# 2. Pick the new release tag (use an .env file or export)
export YUZU_VERSION=0.10.1

# 3. Pull the new image and recreate the container
docker compose -f docker-compose.reference.yml pull server
docker compose -f docker-compose.reference.yml up -d server

# 4. Verify the new version came up and schema migrations ran
docker compose -f docker-compose.reference.yml logs server | tail -40
docker compose -f docker-compose.reference.yml ps server    # should be "healthy"
```

Schema migrations execute automatically during the first `up` with the new image — look for `MigrationRunner: <store> migrated to v<N>` lines in the log (one per store on first upgrade, silent on subsequent restarts). The healthcheck used by `depends_on: service_healthy` probes `/readyz`, which returns 200 only after every store in the readiness conjunction has successfully migrated — so a healthy server container genuinely reflects migration success, not just liveness.

**Back up before upgrading.** Compose prefixes each volume name with the project name, which is the name of the directory holding the compose file unless you set one (`-p`, `COMPOSE_PROJECT_NAME`, or a top-level `name:`); from `deploy/docker` the volumes are `docker_server-data` and `docker_certs`. `docker volume ls` prints the full names. Set `P` to your project name, then run the block from a dedicated backup directory so `$PWD` is predictable. It checks that both volumes exist first, because `docker run -v <name>:...` silently creates an empty volume for a name that does not. Postgres is dumped first, then the keys: key files only accumulate, so a keys archive taken after the dump holds every key the dump references ([the KEK pairing rule](../ops-runbooks/auth-db-recovery.md#backup--the-kek-pairing-rule)). `pg_dump` is consistent against a live database, so no stop is needed for it. The keys archive holds the CA private key, so it is written owner-only and handed to you; keep it outside any git checkout.

```bash
P=docker
mkdir -p ~/yuzu-backups && chmod 700 ~/yuzu-backups && cd ~/yuzu-backups
STAMP=$(date +%F)
docker volume inspect "${P}_server-data" "${P}_certs" > /dev/null \
  && docker exec yuzu-postgres pg_dump -U postgres --format=custom yuzu > "yuzu-pg-$STAMP.dump" \
  && docker run --rm -v "${P}_server-data":/data -v "$PWD":/backup alpine \
       tar czf "/backup/yuzu-data-$STAMP.tar.gz" -C /data . \
  && docker run --rm -v "${P}_certs":/certs -v "$PWD":/backup alpine \
       sh -c "umask 077; tar czf /backup/yuzu-keys-$STAMP.tar.gz -C / certs && chown $(id -u):$(id -g) /backup/yuzu-keys-$STAMP.tar.gz" \
  && echo "OK: backup written to $PWD"
```

> **Note:** this recipe is a cold-ish backup — SQLite is running in WAL mode and a filesystem-level `tar` of a live database may capture a torn snapshot. For strong consistency, `docker compose -f docker-compose.reference.yml stop server` before backup (seconds of downtime) and `start` after. A fully hot backup via SQLite's online-backup API is tracked in the roadmap. The `pg_dump` half has no such caveat — logical dumps are transactionally consistent by construction. **Never** back up Postgres by `tar`-ing the `postgres-data` volume while the database is running; a torn copy of `pg_wal/` is unrecoverable, which is why the procedure above dumps through the database instead.

> **Restore-pairing (ADR-0010):** since 0.14.0 the Postgres dump contains envelope-encrypted secrets (ciphertext + wrapped DEKs only) and is unusable without the matching `KeyProvider` keys directory, the `certs` volume above. Back up and restore the two **as a pair**: capture order and the full procedure are in [the KEK pairing rule](../ops-runbooks/auth-db-recovery.md#backup--the-kek-pairing-rule); see also [Server Administration § PostgreSQL Substrate](server-admin.md#postgresql-substrate).

**Rollback if a migration fails** (Docker). Set `P` to your compose project name, as in the backup above (`docker volume ls` prints the full volume names):

```bash
# 1. Stop the new server (KEEPING the named volume — do NOT use -v)
docker compose -f docker-compose.reference.yml down server

# 2. Restore the previous backup over the existing volume
docker volume inspect "${P}_server-data" > /dev/null && \
docker run --rm -v "${P}_server-data":/data -v "$PWD":/backup alpine \
  sh -c 'rm -rf /data/* && tar xzf /backup/yuzu-data-YYYY-MM-DD.tar.gz -C /data'

# 2b. Restore the Postgres dump (postgres container still running)
docker exec -i yuzu-postgres pg_restore --clean --if-exists --no-owner \
  --role=yuzu -U postgres --dbname=yuzu < "yuzu-pg-YYYY-MM-DD.dump"

# 3. Pin the previous release
export YUZU_VERSION=0.9.0

# 4. Start the previous version
docker compose -f docker-compose.reference.yml up -d server
```

**Never** run `docker compose down -v` unless you intend to delete `server-data`, the keys volume (`certs` in the reference composes, `server-certs` in the others: the CA and the secrets KEK), `postgres-data` (the PostgreSQL substrate — the server's primary data store), and every bit of server state. `down` alone is safe; the `-v` flag removes named volumes.

### Windows

```powershell
# 1. Stop the service (if running as service) or kill the process
Stop-Service yuzu-server  # or: taskkill /IM yuzu-server.exe /F

# 2. Back up data
Copy-Item C:\ProgramData\Yuzu\*.db C:\ProgramData\Yuzu\backup\
Copy-Item C:\ProgramData\Yuzu\*.cfg C:\ProgramData\Yuzu\backup\

# 3. Replace the binary
Copy-Item yuzu-server.exe "C:\Program Files\Yuzu\yuzu-server.exe"

# 4. Start
Start-Service yuzu-server  # or start manually
```

## Upgrading the Gateway

If the server was restarted while this gateway stayed connected, see [What happens when the server restarts](gateway.md#what-happens-when-the-server-restarts) first. The server is upgraded first, so the server restart that ships this fix meets the OLD gateway, and agents behind it can read offline until the gateway is upgraded. Upgrade the gateway and restart it: this version's gateway then recovers a later server restart by itself. A gateway restart disconnects every agent that gateway holds, so it is a fleet-wide reconnect for it, and released v0.13.0 and v0.14.0-rc6 agents with default settings stayed wedged after a graceful gateway restart in testing (v0.12.0 never re-registered; bug #2182, fixed by #5183, in no release tag yet): upgrade the agents to a build that includes #5183 first, or expect to restart the agent service on those agents (see "Agent dependency" in the section linked above). Whether restarting only the gateway recovers agents stranded by an earlier server restart was not tested.

### Linux (systemd)

> **Breaking (#659):** the gateway refuses to start without a non-default Erlang
> distribution cookie. `.deb`/`.rpm` installs auto-generate `/etc/yuzu/gateway.env`;
> for tarball/manual installs create it once (see "Gateway distribution cookie now
> required" under *Upgrade notes by release* below) before the restart step.
>
> **Breaking (`#4555`):** the cookie must additionally be **32+ characters**
> (every documented generation path already clears this), and the gateway's
> Erlang node short name changed from `yuzu_gw1` to a shared `yuzu_gw` — update
> any external tooling hardcoding the old full node name. See "Gateway
> distribution-cookie length floor + shared node identity" below.

```bash
sudo systemctl stop yuzu-gateway
# Replace the release directory
sudo rm -rf /opt/yuzu_gw
sudo tar xzf yuzu-gateway-linux-x64.tar.gz -C /opt/
sudo systemctl start yuzu-gateway
```

### Docker

```bash
docker pull ghcr.io/<owner>/yuzu-gateway:v0.1.1
docker compose up -d yuzu-gateway
```

## Upgrading Agents

### OTA (Recommended)

If the server has OTA updates enabled (`--update-dir`):

1. Place the new agent binary in the server's update directory
2. Agents will check for updates on their configured interval (default: 6 hours)
3. Monitor the fleet dashboard for version rollout progress

### Manual

Follow the same stop/replace/start pattern as the server, per platform.

### Batch Rollout

For large fleets, upgrade in stages:
1. Upgrade a pilot group (5-10 agents) first
2. Monitor for 24 hours
3. Roll out to remaining agents in batches of 10-20%

## Plugin Code Signing (vNEXT, #80)

A new operator-managed plugin trust bundle ships in this release. **Default behaviour is unchanged**: agents that don't pass `--plugin-trust-bundle` and operators that don't upload a bundle through Settings → Plugin Code Signing see identical behaviour to prior releases.

If you turn the feature on, three things change:

1. **New on-disk artifact at `<cert-dir>/plugin-trust-bundle.pem`.** Linux/macOS: `/etc/yuzu/certs/plugin-trust-bundle.pem`; Windows: `C:\ProgramData\Yuzu\certs\plugin-trust-bundle.pem`. **Add this path to your backup procedure** alongside the SQLite databases. A backup that captures the DBs but not the cert dir restores `plugin_signing_required=true` (in `runtime_config`) without the bundle, and require-mode agents reject every plugin until the bundle is restored. The Docker reference `docker-compose.reference.yml` mounts `server-data` and `certs` (the cert dir); include both in the backup script. A compose of your own must keep the cert dir on a named volume too.

2. **Cert-dir filename collision check.** The server now treats `plugin-trust-bundle.pem` in the cert dir as authoritative. The filename was unused in prior releases, but if any deployment placed an unrelated PEM at that exact path for another purpose, it will be interpreted as the plugin trust bundle on first read after upgrade. Run `ls <cert-dir>/plugin-trust-bundle.pem` on every server host before upgrading and rename any pre-existing file.

3. **DO NOT enable "Require signed plugins" yet.** The Yuzu release pipeline does not currently sign the 44 in-tree plugins under `agents/plugins/`. Enabling Require with an operator-only trust bundle will reject every Yuzu-shipped plugin on next agent restart — fleet-wide outage. Use the transitional mode (bundle uploaded, Require off) until you have signed every plugin your fleet uses, including the in-tree ones. The Settings card displays this warning inline.

The new audit actions (`plugin_signing.bundle.uploaded` / `.cleared` / `.require.changed`) and metric labels on `yuzu_agent_plugin_rejected_total` (`signature_missing` / `signature_invalid` / `signature_untrusted_chain`) are documented in `audit-log.md` and `metrics.md` respectively. SIEM and alert rules already filtering on the existing `success`/`failure`/`denied` audit vocabulary pick these up unchanged — no new vocabulary tokens were introduced.

## Schema Migrations

Starting with **v0.10.0**, every server-side SQLite store is wired through a single `MigrationRunner` that tracks schema version per store and applies pending migrations in a transaction. Prior releases relied on `CREATE TABLE IF NOT EXISTS` plus silent `ALTER TABLE ADD COLUMN` statements, which made rollbacks opaque and left no audit trail of what had been applied.

How it works:

- Each store declares an ordered `std::vector<Migration>` where each entry is `{version, sql}`.
- On startup, the runner creates the `schema_meta` table if missing, reads the current version for the store, and runs any migration with a higher version number inside a `BEGIN IMMEDIATE` / `COMMIT` transaction.
- If a migration SQL statement fails, the transaction rolls back and the store stays at its previous version — the server logs `MigrationRunner: migration v<N> failed for <store>: <sqlite error>` and the corresponding store constructor logs `<Store>: schema migration failed`.
- Already-applied migrations are skipped; running the same server binary twice against the same database is a no-op.
- Multiple stores share one database connection but keep independent version counters.

**Indexes are normally migration entries. `audit_store`'s retention index is a
deliberate, single exception** (`idx_audit_ttl_id`, #2360) - every other index in
the server is created inside `MigrationRunner`, and new code should follow that
rule, not this one. Two conditions justify the exception here and both must hold
before it is copied: (a) a failed migration closes the store, and for
`audit_store` that means every audit write then fails, taking the SOC 2 trail
offline; and (b) the build is `O(N log N)` over an existing multi-million-row
table, unlike the v1 indexes which are created on an empty one. A best-effort
object may silently not exist, so nothing with a CORRECTNESS dependency may use
this path - the retention guard is correct without its index, only slower.

Cost on a large existing `audit_events`: a one-time build at first boot after
upgrade, measured at ~81 MB and ~1.8-3.3 s at 5M rows on NVMe. At 50M rows the
build reads a ~16 GB table - tens of seconds on local NVMe, and potentially
minutes on container overlayfs or network storage.

**This runs synchronously, before the server binds its listeners**, so nothing
answers `/livez` or `/readyz` until it finishes. If your orchestrator's
kill-before-ready budget is shorter than the build you get a CRASH LOOP rather
than a slow boot: `CREATE INDEX` is one atomic statement, so every killed attempt
rolls back and the next boot re-pays it in full, indefinitely. Budget at least
**5 minutes** before the first liveness kill for an `audit_events` above ~20M
rows on non-NVMe storage. The shipped
`deploy/docker/docker-compose.reference.yml` sets `start_period: 30s`, which is
fine for a fresh install and NOT enough for a large first post-upgrade boot -
raise it before upgrading such a deployment. The
elapsed time is logged when it exceeds a second, and subsequent boots are a
no-op. If the build fails, retention still runs, but each pass then scans the
table AND sorts the whole expired backlog for its `ORDER BY ... LIMIT` (measured
2.0 s versus ~285-315 ms for the same capped pass WITH the index; the range
reflects different benchmark runs, not two different operations) - still far better than the unguarded code it
replaced, but the failure is logged as an error.

**Upgrading from v0.9.x or earlier** is data-preserving: the first 0.10.x startup stamps every database at schema v1. A small set of stores (`api_token_store`, `instruction_store`, `patch_manager`, `policy_store`, `product_pack_store`, `response_store`) also runs a one-time legacy compatibility shim that re-applies the historical `ALTER TABLE` statements before stamping, so databases from very old releases that never received those columns still converge to the latest schema. These shims are kept in code for one release cycle and can be removed after v0.11.

**No manual migration steps are required.** Just replace the binary (or pull the new image and `up -d`) and start the server. Migration progress is logged at `info` level as:

```
[info] MigrationRunner: rbac_store migrated to v1
[info] MigrationRunner: response_store migrated to v1
...
```

**Expect a log burst on first startup after upgrade.** 30+ `MigrationRunner: <store> migrated to v1` info lines appear on the first run against a pre-v0.10 database — one per store. On every subsequent restart the runner is silent at info level. If your log-shipping pipeline has per-second rate limits, widen them for the upgrade window or filter this single line pattern.

**Verifying migration state after startup**, query the per-store audit trail directly:

```bash
docker exec -i yuzu-server sqlite3 /var/lib/yuzu/rbac.db \
  "SELECT store, version, datetime(upgraded_at, 'unixepoch') FROM schema_meta ORDER BY upgraded_at;"
```

Every store that has ever run through the migration runner has a row here with its current version and the wall-clock timestamp of the last stamp. This is the operator-side audit trail for schema evolution.

**The Postgres-backed stores are not in that file.** Stores migrated onto the PostgreSQL
substrate — `audit_store` among them (ADR-0040) — run through `PgMigrationRunner`, log
`PgMigrationRunner: <store> migrated to v<N>`, and stamp `public.schema_meta` **in
PostgreSQL**. Query those there instead:

```bash
psql "$YUZU_POSTGRES_DSN" -c \
  "SELECT store, version, to_timestamp(upgraded_at) FROM public.schema_meta ORDER BY upgraded_at;"
```

For `audit_store` specifically, a legacy `audit.db` — if one still exists — is never renamed,
moved, or modified: Yuzu only opens it read-only, at boot, to warn if it holds rows (see the
Audit trail section above). `sqlite3 /var/lib/yuzu/audit.db` still opens it normally on a
migrated server; there is nothing to restore or account for here.

If a migration fails:

1. Check the log for `MigrationRunner: migration v<N> failed for <store>: <sqlite error>` and note both the store name and the SQLite error.
2. The server will have **closed the failing store's database handle**, so `/readyz` returns 503 with the failed store name in the `failed_stores` body field — the probe accurately reflects degraded state. Don't rely on `/livez` for readiness; it only checks process liveness, not schema integrity.
3. Stop the server and restore the **affected** database file from backup — not the whole data directory. Restoring all databases to fix one broken store wipes in-flight approvals, pending agents, and enrollment tokens. **This step does not apply to a Postgres-backed store** such as `audit_store`: there is no per-store file to restore, so use the Postgres dump procedure under "Rollback if a migration fails" above.
4. Start the previous server version against the restored data.
5. Open an issue with the full error line, the source/target version numbers, and the output of the `schema_meta` query above.

## Upgrade notes by release

### vNEXT — Decommission securable replaces the SLE/Inventory/GuaranteedState conjunction (breaking for custom roles)

`DELETE /api/v1/sle/agents/{id}` (the whole-device erasure cascade — see
[REST API § Software Licensing (SLE)](rest-api.md#software-licensing-sle)) used to gate on a
**three-securable conjunction**: `SoftwareLicensing:Delete` **and** `Inventory:Delete` **and**
`GuaranteedState:Delete`, all required together. A companion Wave 7 PR7.2 package adds a sixth
per-agent store (`app_usage`) to the cascade (and #5682 a seventh, `offline_endpoint`, for seven
in total), and rather than grow the conjunction to a fourth securable, ADR-0024 Decision 9 was
amended ahead of that landing to promote a single dedicated **`Decommission`** securable — the
route now gates on **`Decommission:Delete` alone**, replacing the old conjunction outright (not
adding to it).

**Seeded roles are auto-preserved** — the same `INSERT OR IGNORE` role-default seeding as the SLE
securable above runs on every boot, so `Administrator` (full CRUD via the generic per-securable
loop) and `ITServiceOwner` (a targeted `Decommission:Delete` grant) pick up the new securable
automatically on upgrade, with no operator action required.

**A previously revoked decommission ability is NOT silently regained.** If you had used
`remove_permission()` to revoke `ITServiceOwner`'s `SoftwareLicensing:Delete`,
`Inventory:Delete`, or `GuaranteedState:Delete` specifically to strip its decommission ability
under the old conjunction, the upgrade detects that revocation and carries it forward onto the new
`Decommission:Delete` grant automatically — `ITServiceOwner` stays unable to decommission a device
after upgrading, exactly as before. No operator action is needed for this case; it is the inverse
of the custom-role gap above (a seeded role *losing* access it deliberately had revoked is checked
for, not just a custom role *gaining* an unrelated 403).

**This is breaking only for a custom role.** Any custom role an operator built by hand-assembling
the old three-securable conjunction (`SoftwareLicensing:Delete` + `Inventory:Delete` +
`GuaranteedState:Delete`) specifically to reach this endpoint will start getting `403 Decommission:Delete`
on its next call — **the three old grants no longer suffice**, because the route no longer checks
them at all. Audit your custom roles before upgrading:

```sql
SELECT pr.principal_type, pr.principal_id, pr.role_name
  FROM rbac_store.principal_roles pr
  JOIN rbac_store.role_permissions rp ON rp.role_name = pr.role_name
  WHERE rp.securable_type IN ('SoftwareLicensing', 'Inventory', 'GuaranteedState')
    AND rp.operation = 'Delete'
    AND rp.effect = 'allow'
  GROUP BY pr.principal_type, pr.principal_id, pr.role_name
  HAVING COUNT(DISTINCT rp.securable_type) = 3;
```

The old gate was a strict three-way AND — all three grants required together, `effect = 'allow'`
on each. Matching on any ONE of the three (or including an explicit `effect = 'deny'` row, a legal
`role_permissions` state) over-reports: a role holding, say, only `Inventory:Delete` for an
unrelated purpose never had decommission ability under the old conjunction, and granting it
`Decommission:Delete` now would be a NEW grant, not a preserved one.

Grant `Decommission:Delete` to any custom role in that list that must retain the ability to erase a
decommissioned device's data. `SoftwareLicensing:Delete`, `Inventory:Delete`, and
`GuaranteedState:Delete` continue to gate their own unrelated surfaces exactly as before — only the
erasure cascade's gate moved.

**Rolling upgrade (the seventh store, `offline_endpoint`).** During a rolling upgrade, a DELETE
served by a replica that has not been upgraded runs the old cascade, returns `200`, and does not
erase the presence row; a response whose `stores` map has no `offline_endpoint` key did not erase
it, and the `sle.agent.decommission` success audit row that replica writes lists its own stores
(no `offline_endpoint`), so it is not evidence the presence row was erased. Re-issue the DELETE
once every replica runs this version.

### vNEXT — Hardware CI list requires `Inventory:Read`, not the old Devices page's `Infrastructure:Read` (breaking for custom roles)

`/devices` now 302-redirects to `/hardware` (the Hardware CI list) and `/device?id=` redirects to
`/hardware/ci?id=` — bookmarked links and existing browser navigation keep working transparently,
since browsers follow redirects. The **permission the list itself checks** changed, though: the old
Devices page gated on `Infrastructure:Read`; the Hardware CI list gates on `Inventory:Read` (the
same securable the rest of the Inventory/Software surface already uses).

**Seeded roles are unaffected.** Every built-in role that held `Infrastructure:Read` (Administrator,
ITServiceOwner) also holds `Inventory:Read`, so no default-role regression on upgrade.

**This is breaking only for a custom role granted `Infrastructure:Read` without `Inventory:Read`.**
Such a role could see the device list via the old `/devices` page pre-upgrade and will get a `403`
reaching the redirected `/hardware` page post-upgrade. Audit custom roles before upgrading:

```sql
SELECT pr.principal_type, pr.principal_id, pr.role_name
  FROM rbac_store.principal_roles pr
  JOIN rbac_store.role_permissions rp ON rp.role_name = pr.role_name
  WHERE rp.securable_type = 'Infrastructure' AND rp.operation = 'Read' AND rp.effect = 'allow'
    AND NOT EXISTS (
      SELECT 1 FROM rbac_store.role_permissions rp2
      WHERE rp2.role_name = pr.role_name
        AND rp2.securable_type = 'Inventory' AND rp2.operation = 'Read' AND rp2.effect = 'allow'
    );
```

Grant `Inventory:Read` to any custom role in that list that must retain device-list visibility.
`Infrastructure:Read` continues to gate the fleet-wide agent list (`/api/agents`) and other
infrastructure-tier reads exactly as before — only the Hardware CI list's own gate moved.

### Retention clock guards (#2360 server audit store, #2361 TAR agent warehouse, #2964 rotation sweep)

Both retention paths used to issue an unbounded `DELETE` driven by the local wall
clock, so one forward clock step could wipe a store in a single statement. They
are now guarded and capped. Two operator-visible consequences on upgrade:

- **Audit retention is now a floor, not a ceiling.** A pass that would expire
  every datable row declines once, and every accepted pass is capped at 25,000
  rows, so a large backlog ages out over hours rather than in one statement.
  Watch `yuzu_server_audit_retention_cap_reached_total` alongside
  `yuzu_server_audit_rows_deleted_total` to see whether a backlog is draining.
  The cap paces at two different cadences depending on whether a backlog is
  forming — see [Audit Log § Capacity](audit-log.md#capacity) for both
  figures; comparing your event rate against only the quiet-operation one is
  overly conservative by roughly three orders of magnitude. Note that
  changing `--audit-retention-days` never re-dates
  existing rows (`ttl_expires_at` is stamped at INSERT), so a reduction does not
  reclaim disk retroactively. Operator triage when the guard declines a pass:
  [audit-log.md § The retention clock guard](audit-log.md#the-retention-clock-guard).
- **`audit_store` gains schema v3** (a small `audit_retention_meta` key/value
  table holding the durable clock reading - one row, instant) plus the
  best-effort index build described under Schema Migrations above.
- **`YuzuAuditRetentionNotRunning` now fires for a crash-looping server
  (#2553, redesigned by #2854 rung D), and there is a new
  `YuzuAuditRetentionNeverRan` alert to route.** The old rule's young-server
  grace keyed on uptime, so a process restarting more often than the 3-hour
  alert window never accumulated enough uptime to leave the grace and was
  excused on every evaluation - silently, and for one of the leading causes of
  the exact condition the rule detects. The grace is now the restart-surviving
  last-pass stamp (`yuzu_server_audit_retention_last_pass_unixtime`, seeded
  from the durable anchor at startup): the rule excuses only a database no
  retention pass has EVER run against, fires at every restart cadence on an
  anchored one, and stays firing while the reaper stays dead. The excused
  never-ran state gets its own alert, `YuzuAuditRetentionNeverRan` (stamp
  still `0` after 3 hours) - **a new alertname: give it an Alertmanager route**.
  **If you re-apply this rules file and have a crash-looping server, expect a
  new-to-you firing** that reflects a pre-existing condition rather than a new
  fault - including on crash loops faster than the 60-minute first-pass sleep,
  a true positive the old grace hid. The rules file is a copy you apply
  yourself; the server does not upgrade it for you, and a stack that does not
  re-apply it keeps the old blind rule and never gains the new alert. In a
  staged rollout apply SERVERS first, rules second: an old, not-yet-upgraded
  server restarting under the new rules reads a `0` stamp even on an anchored
  database and pages `YuzuAuditRetentionNeverRan` with a fresh-install story
  that is false for it (see the runbook's rollout note). The same
  re-apply also removes an `on(instance)` join from the liveness rule, so a
  server that was being silenced by an unrelated series sharing its `instance`
  value (a canary, an HA pair, a federated series) can now correctly fire too -
  the same new-to-you-firing shape as the crash-loop fix, for the same reason.
- **You must ADD a new rule by hand: `YuzuAuditRetentionMetricMissing` (#2553).**
  `YuzuAuditRetentionNotRunning` cannot detect its own input going missing -
  `increase()` over a metric with no series is an empty vector, so the rule selects
  nothing and never fires. A Prometheus holding these rules against a server that
  does not export `yuzu_server_audit_retention_passes_total` therefore reports
  healthy forever while the audit reaper is entirely unmonitored, which is exactly
  the state you are in if you apply this rules file ahead of upgrading your
  servers. The new rule keys on `absent(...)` and fires after 15m. It is
  **fleet-wide by construction**: it cannot see one server among many going quiet.
  **A `up`-based target-down alert does NOT close that gap** — a server that is
  running an older build is alive and scraped, so its `up` is 1; it simply does
  not export this counter. Measured (#2553): in a fleet where one server exports
  the counter and another does not, *neither* retention rule fires, for either
  server, indefinitely. During a staged upgrade the practical mitigation is to
  confirm coverage directly rather than to rely on an alert —
  `count(yuzu_server_audit_retention_passes_total)` against your expected server
  count — until every server is upgraded. A per-target rule for this is tracked
  separately.
- **The first guarded pass now declines when it has no stored reading and rows
  are already expired (#2579).** The stored clock reading (the anchor) is new in
  schema v3, so every database starts its first guarded pass without one. An
  ABSENT reading is not a statement about the clock - it is the ordinary
  fresh-install case - which previously left one shape unguarded: a host already
  skewed FORWARD, where rows written after the skew were still inside the window,
  so the would-expire-everything test did not fire either, and the pass deleted up
  to the 25,000-row cap unremarked. Such a pass now declines ONCE, warns, and
  anchors the reading; the next pass proceeds normally, paced by the cap. A fresh
  install with nothing expired does not decline at all. **Expect at most one such
  decline per server on this upgrade**, counted by the new
  `yuzu_server_audit_retention_bootstrap_declines_total` and NOT by
  `yuzu_server_audit_clock_anomaly_skips_total` - so it does not fire
  `YuzuAuditRetentionClockAnomaly`, and you should not stand that alert down for
  it. Servers upgrading FROM an affected version with a wrong clock may already
  have lost rows; there is no reliable retrospective test, and the loss is not
  recoverable without a backup predating it. Detail:
  [audit-log.md § The retention clock
  guard](audit-log.md#the-retention-clock-guard).
- **Expect a first-pass retention decline on the AGENT, and only conditionally on
  the server.** The two guards differ here and the difference matters:
  - **TAR declines on a missing anchor, by design.** It checks per warehouse
    table, so on an agent upgrade every enabled time-based table declines in that
    same pass and `retention_guard_declines_total` rises by the number of those
    tables (5-10 on a default agent), not by 1. That is the benign bootstrap
    case, not a fleet of separate anomalies, and it needs no action.
  - **The audit store's triggers are NOT the same**, so do not carry the agent's
    expectation across to it and do not pre-emptively stand down
    `YuzuAuditRetentionClockAnomaly` on a fleet upgrade. If one fires, work it as
    an alert rather than assuming a benign bootstrap:
    [audit-log.md § The retention clock guard](audit-log.md#the-retention-clock-guard)
    states when the server's guard declines, and
    [the ops runbook](../ops-runbooks/audit-store-clock-guard.md) is the response
    path.
- **Agents surface new `tar status` lines**: `storage_state`,
  `retention_guard_declines_total`, `retention_guard_failures_total`, and
  per-table detail. On the healthy path `storage_state|ok` is the first line,
  and existing consumers filter on the `config|` prefix and ignore unknown
  lines, so nothing breaks. **On the offline path they do break**: when the TAR
  database has been closed after a wedged rollback, `tar status` returns
  non-zero and emits only an `error|` line followed by `storage_state|offline` -
  no `record_count`, no `config|` lines at all. Note the order is REVERSED
  there: `error|` comes first, because server and dashboard consumers key off
  the output starting with `error|`. A consumer keyed on the presence of
  `record_count` must handle that. See
  [tar.md](tar.md#the-retention-clock-guard). TAR persists its own clock reading
  in `tar_config` (`retention_guard_last_pass`) - no schema change.
- **TAR row-count retention is now paced.** Its ceiling semantics are unchanged,
  but a large excess (after a long disable, or an upgrade backlog) drains over
  several 900 s rollup ticks rather than in one statement.
- **`ApiTokenStore` gains a THIRD, independent clock guard (#2964) — the
  rotation sweep that auto-revokes rotation predecessors.** Same shape as the
  audit store's, same schema-migration pattern (a new `rotation_retention_meta`
  key/value table holding the durable anchor), same bootstrap-decline
  consequence, but a much shorter cadence: this sweep ticks every 60 seconds,
  not hourly. **If you are upgrading a populated store that already has
  elapsed, not-yet-swept rotation pairs** — a predecessor whose overlap
  window has already ended, sitting there because nothing has run the guard
  against it before — **expect the sweep's first tick after the migration to
  decline once**, the same "no durable anchor yet, and there is already
  something eligible" bootstrap case #2579 describes for the audit store.
  Both credentials in every affected pair simply stay active for that one
  tick; the very next tick has an anchor and proceeds normally, so at a
  60-second cadence this resolves in roughly two minutes, not the audit
  store's next-hourly-pass timescale. Nothing is lost or at risk here (an
  auto-revoke deferred by one tick is the intended failure mode, not the
  audit store's deletion-risk case) — this is a heads-up so the log line and
  the one-off decline are not mistaken for something wrong with the upgrade.
  See `docs/user-manual/metrics.md` "Rotation-sweep clock guard metrics" and
  `docs/ops-runbooks/rotation-sweep-clock-guard.md`.

New Prometheus alert rules ship in `docs/prometheus/yuzu-alerts.yml`, which is the
current set. The declined-pass and failed-pass
counters must be alerted on separately: both leave rows undeleted, so an audit
table that never shrinks looks identical either way. One rule,
`YuzuAuditRetentionNotRunning`, fires on the reaper NOT running - the state in
which none of the other counter-driven rules can fire, because they all key on a
counter rising.

### SLE — the `SoftwareLicensing` securable auto-grants on upgrade (ADR-0024)

This release adds the **SLE** (Software Licensing & Entitlements) **discovery** surface,
gated on a new **`SoftwareLicensing`** RBAC securable. Per **ADR-1005** the server ships
the discovery mechanism only: the per-device **`GET /api/v1/sle/agents/{id}`** drill, its
machine-scope MCP twin `query_software_licenses`, and the audited erasure
**`DELETE /api/v1/sle/agents/{id}`**. The licence **compliance / entitlement / reclamation**
views and the fleet **posture** reads (a `/sle` page and `/api/v1/sle/summary` ·
`/licenses` · the per-product device fan-out) **interpret** discovered facts and ship with
the future **SAM use-case-engine module** — they are *not* in this release, so a reader
who saw the earlier ADR expecting an in-server compliance page should not look for one yet.
Because RBAC role defaults are seeded with `INSERT OR IGNORE` on **every** boot, an
upgrading deployment **silently auto-grants** the new securable to the built-in roles the
first time it starts the new build:

| Role | Grant |
|---|---|
| Viewer, PlatformEngineer | Read |
| Operator | Read + Write |
| ITServiceOwner, Administrator | full CRUD |
| ApiTokenManager | none |

**No action is required** if that matches your intent — the securable gates the SLE
discovery reads/erasure (`GET`/`DELETE /api/v1/sle/agents/{id}` and the MCP twin); the
`/inventory` software catalog is unchanged and remains under `Inventory:Read`.

**But** the per-device drill exposes each endpoint's **detected-licence facts** —
product, vendor, channel, status, expiry, and, on per-user surfaces, the per-user
**`user_ref`** identifier — **to every Read holder, including `Viewer`**. **A deployment
that must restrict this visibility should deny or remove the `SoftwareLicensing` Read
grant from `Viewer` (and any other broad role) BEFORE enabling the SLE sources.** A
**deny rule wins** over the seeded allow (deny-override), so an explicit deny is the
durable control — re-seeding on the next boot cannot re-open it. (Entitlement/purchase
**cost** metadata is *not* served in-server this release — it is the SAM UCE module's,
governed by that module's own RBAC when it ships.)

The SLE detection source also collects a new, suppressible **per-user identifier**
(`user_ref`) on per-user licence surfaces. It defaults to a per-device keyed-HMAC
pseudonym; see [Software licence detection](software-licensing.md) for the
`--license-scan-user-ref` flag, the honest limits of that default, and the
`--inventory-disable` source-level opt-out.

### Gateway distribution cookie now required (#659) — **BREAKING**

The Erlang gateway shipped a hardcoded default distribution cookie
(`yuzu_gw_secret_change_me`). The cookie is the sole authentication for
inter-node RPC, so a publicly-known value is unauthenticated remote code
execution for anyone who can reach EPMD (TCP 4369). The gateway now **refuses to
boot** with the default (or an empty/unsubstituted) cookie unless explicitly
overridden.

**Before upgrading:**

- **`.deb` / `.rpm` installs** auto-generate a unique cookie into
  `/etc/yuzu/gateway.env` (mode `0640`, `root:yuzu-gw`) on first install and
  never clobber it on upgrade — no action needed for a single node.
- **Tarball / manual systemd installs** must create the env file once:
  ```bash
  sudo install -d -m 0755 /etc/yuzu
  printf 'YUZU_GW_COOKIE=%s\n' "$(openssl rand -hex 32)" | sudo tee /etc/yuzu/gateway.env >/dev/null
  sudo chown root:yuzu-gw /etc/yuzu/gateway.env && sudo chmod 0640 /etc/yuzu/gateway.env
  ```
  The systemd unit loads it via `EnvironmentFile=-/etc/yuzu/gateway.env`.
- **Docker / Compose** deployments must set `YUZU_GW_COOKIE` in the gateway
  service environment (e.g. `export YUZU_GW_COOKIE=$(openssl rand -hex 32)` then
  reference it). Dev/CI may instead set `YUZU_GW_ALLOW_DEFAULT_COOKIE=1`.
- **Multi-node clusters:** every node must share the **same** cookie — set an
  identical `YUZU_GW_COOKIE` (or write the same `/etc/yuzu/gateway.env`) on all
  nodes; the per-host auto-generated value will NOT match across hosts.

**Recovery — gateway won't start after upgrade:**

| Symptom | Diagnose | Fix |
|---|---|---|
| `systemctl status yuzu-gateway` shows `start-limit-hit` / `failed` | `journalctl -t yuzu-gateway \| grep -i cookie` shows "insecure distribution cookie" (for manual/`foreground` or container runs, check stdout / `gateway.log` instead) | Create `/etc/yuzu/gateway.env` with `YUZU_GW_COOKIE=$(openssl rand -hex 32)` (see above), then `systemctl reset-failed yuzu-gateway && systemctl start yuzu-gateway`. **Do not** use `YUZU_GW_ALLOW_DEFAULT_COOKIE=1` in production. |
| Gateway container restarts at boot on an AMX-capable Intel host (Sapphire Rapids+, AWS c7i/m7i/r7i) | Container log has `sys_sigaltstack(): Internal error: Failed to set alternate signal stack`; image is 0.13.0 through 0.14.0-rc4 (#2150) | Pull an image that carries the #2150 fix (0.14.0-rc5 or later). Until then, run the gateway on a host without AMX. A single-node gateway may use `yuzu-gateway-chisel` instead; a clustered one may not (it never joins the cluster). Do not roll back to 0.13.0 on that host: it is affected too. |

> The generated `/etc/yuzu/gateway.env` is intentionally **preserved across
> `apt purge` / `rpm -e`** (the `/etc/yuzu` directory may be shared with other
> Yuzu packages). To remove the cookie after uninstall: `sudo shred -u /etc/yuzu/gateway.env`.

> **Never set `YUZU_GW_ALLOW_DEFAULT_COOKIE=1` in production** — it disables the
> guard and restores the unauthenticated-RPC surface. It exists only for
> ephemeral dev/CI stacks.

### Gateway distribution-cookie length floor + shared node identity (HA WS-4 `#4555`) — **BREAKING**

Extends the `#659` cookie requirement above with two further changes, both
shipped together as part of gateway multi-node cluster formation:

- **Cookie length floor.** The gateway now additionally refuses to boot with
  a distribution cookie **shorter than 32 characters**, even a genuinely
  custom (non-default) one. DNS-based cluster discovery means a node now
  dials addresses it did not choose by hand, and the distribution
  handshake's INITIATOR sends the cookie hash first — a short cookie is
  brute-forceable offline from a legitimately-dialing node. **Every
  documented cookie-generation path already clears this floor with room to
  spare** (`openssl rand -hex 32` produces 64 characters) — no action
  needed if you followed the `#659` guidance above verbatim. Only an
  operator who hand-picked a short custom cookie is affected; the same
  `YUZU_GW_ALLOW_DEFAULT_COOKIE=1` override (dev/CI only, never production)
  bypasses this check too.
- **Node identity change.** The Erlang node short name changed from a
  hardcoded `yuzu_gw1` to a shared `yuzu_gw` — every gateway replica in a
  cluster now advertises the SAME short name, distinguished only by an
  address resolved at boot (`YUZU_GW_ADVERTISE_ADDR`, auto-detected by
  default), so that identical replicas can boot from one image/env (a
  prerequisite for `docker compose up --scale gateway=N`). A single-node
  deployment boots identically otherwise (the address defaults to
  `127.0.0.1`, matching the old hardcoded value) — but any external
  tooling that hardcodes the OLD full node name (`yuzu_gw1@127.0.0.1`) in a
  `erl -remsh`/`recon` script, a health check, or a monitoring probe will
  silently stop matching after upgrade. Update any such tooling to match
  `yuzu_gw@` (a prefix, since the address suffix may vary).

**Recovery** for the cookie-length case uses the same diagnostic path as
`#659` above (`journalctl -t yuzu-gateway | grep -i cookie` / stdout /
`gateway.log`) — the log line names the specific failure (`shorter than 32
characters`) separately from the known-default rejection.

### InstructionDefinition import signature enforcement now on-by-default (#1073 / W7.4 sibling-gap) — **BREAKING**

`InstructionStore::import_definition_json` (the storage path behind
`POST /api/instructions/import`) previously accepted unsigned JSON
envelopes without verification. After upgrade, unsigned imports are
rejected with:

```
instruction-import is unsigned and signature enforcement is enabled (set --allow-unsigned-definitions / YUZU_ALLOW_UNSIGNED_DEFINITIONS=1 to bypass)
```

This is intentional and closes the sibling-gap to #802. Without the
gate, any operator with `InstructionDefinition:Write` permission can
import a definition that dispatches an arbitrary plugin invocation on
every targeted agent — same fleet-RCE blast radius the pack-signing
default closed.

**Two migration paths, in order of preference:**

1. **Sign your imports.** Generate an Ed25519 keypair, sign the
   `yaml_source` field's bytes with the private key, and wrap the
   envelope with `signature: <hex>` + `publicKey: <hex>` top-level
   fields. The wire format mirrors ProductPack: signature is hex-
   encoded over the verbatim `yaml_source` bytes; `publicKey` is the
   hex-encoded raw Ed25519 public key (32 bytes / 64 hex chars).
   Until the dedicated helper script lands (tracked as a follow-up
   issue covering both pack-signing and definition-signing tooling),
   use the raw `openssl` recipe directly:

   ```bash
   # One-time: generate a keypair (rotate periodically per your policy).
   openssl genpkey -algorithm Ed25519 -out yuzu-signing.pem
   openssl pkey -in yuzu-signing.pem -pubout -outform DER \
       | tail -c 32 | xxd -p -c 64    # → 64-hex publicKey

   # Per definition: sign yaml_source bytes, hex-encode the output.
   echo -n "$YAML_SOURCE" \
       | openssl pkeyutl -sign -inkey yuzu-signing.pem -rawin \
       | xxd -p -c 128                # → 128-hex signature
   ```

   Inject `signature` and `publicKey` as top-level string fields in
   the JSON envelope POSTed to `/api/instructions/import`. See the
   REST API reference (`docs/user-manual/rest-api.md` →
   `POST /api/instructions/import`) for the full signing-rules table
   and per-rejection error strings.

2. **Opt out temporarily** (legacy environments only). Pass
   `--allow-unsigned-definitions` to `yuzu-server` or set
   `YUZU_ALLOW_UNSIGNED_DEFINITIONS=1` in the service environment. The
   server emits an `InstructionStore: signature enforcement DISABLED
   by configuration` warning on every start AND a
   `server.unsigned_definitions_allowed` audit row at boot, so the
   relaxed posture is recoverable from both operator logs and the
   audit store. **Remove the flag** as soon as the signing migration
   completes.

**Pre-existing imported definitions are unaffected.** The gate fires
only on the public import path. The bundled-content boot seed (the
`kBundledDefinitions` baked into `yuzu-server` at build time) routes
through an internal `import_definition_json_trusted` variant that
bypasses the gate; its authenticity comes from binary linkage, not
runtime signature.

**Authoring surfaces are NOT gated.** `POST /api/instructions`,
`POST /api/instructions/yaml`, and `PUT /api/instructions/{id}` — the
dashboard and CLI surfaces where operators author definitions in-
session — continue to trust `InstructionDefinition:Write` as the
author trust boundary (the operator IS the source; there is no
supply chain to authenticate). The `--allow-unsigned-definitions`
flag does NOT affect those surfaces; they have always accepted
unsigned author-time input and continue to. The architectural
question of whether authoring surfaces should ALSO require signed
envelopes is tracked as a follow-up issue with operator-decision-
required framing (UX trade-off: gating authoring would break in-
browser definition authoring).

**Audit-trail evidence chain.** Every rejection emits an
`instruction.import / denied` audit row with the store error string
in `detail` (stable SIEM-keyable tokens listed in the
`audit-log.md` reference). If the audit-store write itself fails
(locked DB, disk full), the response carries `Sec-Audit-Failed: true`
header AND `audit_emitted: false` in the JSON body, surfacing the
SOC 2 CC7.2 evidence gap to the operator immediately rather than
silently dropping the event.

### Product pack signature enforcement now on-by-default (#802 / W7.4) — **BREAKING**

The `ProductPackStore` previously shipped with signature enforcement
**disabled** by default and the setter to enable it was never wired to
any operator-facing flag — the protection was effectively unreachable.
After upgrade, calls to install a `ProductPack` without a `signature:`
field are rejected with:

```
pack '<name>' is unsigned and signature enforcement is enabled (set --allow-unsigned-packs / YUZU_ALLOW_UNSIGNED_PACKS=1 to bypass)
```

This is intentional. Unsigned packs are a fleet-wide arbitrary-code-
execution surface: any operator with `Pack:Install` permission, or a
MITM on pack delivery, could install a pack containing
`InstructionDefinition` or plugin payloads that would then execute on
every enrolled agent.

**Two migration paths, in order of preference:**

1. **Sign your packs.** Generate an Ed25519 keypair, sign each pack's
   non-metadata YAML content with the private key, and add
   `signature: <hex>` + `publicKey: <hex>` fields to each pack's
   `ProductPack` metadata document. The existing verify path
   (`ProductPackStore::verify_signature`) accepts the result. Pack
   install then succeeds and the `verified` column in the store is set
   to true so a future "show only verified packs" query has the data
   it needs.

2. **Opt out temporarily** (legacy environments only). Pass
   `--allow-unsigned-packs` to `yuzu-server` or set
   `YUZU_ALLOW_UNSIGNED_PACKS=1` in the service environment. The
   server emits a `[SECURITY] product pack signature enforcement
   DISABLED by configuration` warning on every start and writes a
   `server.unsigned_packs_allowed` audit row, so the relaxed posture
   is recoverable from both operator logs and the audit store.
   **Remove the flag** as soon as the pack-signing migration completes;
   it is not intended as a permanent configuration.

**Pre-existing installed packs are unaffected.** The check fires only
on the install path (`POST /api/product-packs`). List, get, and
uninstall paths do not re-verify, so already-installed unsigned packs
remain queryable and uninstallable after upgrade.

### vNEXT — Access-review CSV export gains a leading metadata line (breaking for fixed-column-index CSV consumers)

`GET /api/v1/access-reviews/export?format=csv` (SOC 2 CC6.2 evidence) now
emits one new line before the existing header row:

```
# rbac_enforcement=enabled
principal_type,principal_id,display_name,owner_or_email,roles,effective_permission_count,last_activity_ms,last_activity_kind,classification,lifecycle_state,source
user,alice,...
```

This line is unconditional — present even when the grant population is
empty — so it stamps whether RBAC was actually enforced when the file was
pulled, travelling with the retained/offline copy an auditor keeps (see
`rest-api.md`'s `rbac_enforcement` section for what the three values mean).

**This breaks any consumer that assumes row 1 is the header.** Verified
empirically against this exact output shape (not a blanket claim about "CSV
tools" — the actual split matters):

- **Silently WRONG output, no error, no warning:** Python's `csv.DictReader`
  reads the new line 1 as a single-column header, then feeds the REAL header
  row (line 2) into the result set as if it were data — every field name and
  every row is now misaligned. The `awk -F, 'NR>1'` idiom (and any hand-rolled
  "skip the first line" loop in another language) does the same thing: it now
  emits the real header row as a spurious first "data" row, ahead of the
  genuine data rows, which otherwise parse correctly.
- **Also silently WRONG, not a loud failure:** `pandas.read_csv(path)` with
  its default settings does **not** raise `ParserError` on this shape — do
  not rely on pandas to "fail loud" here. Because every row past line 1 is
  uniformly wider than the 1-field metadata line, pandas' documented
  "extra leading columns become an implicit index" heuristic kicks in: it
  silently produces a 1-column, tuple-indexed `DataFrame` with the metadata
  line as the sole column name and the leading fields folded into a
  `MultiIndex`, leaving only the last field (`source`) as the actual,
  mislabeled `DataFrame` column — wrong, but no exception. (Verified
  directly against pandas 3.0.6, both the `c` and `python` engines; on that
  version, neither engine's default settings raise instead of silently
  misparsing — untested against older pandas majors, so treat "on 3.0.6"
  as the scope of this claim, not a guarantee for every pandas release.)

**The fix is the same for every consumer class: skip exactly one line before
treating the next line as the header**, verified working against each tool
above:

```python
# csv.DictReader
with open(path, newline="") as f:
    next(f)                      # skip the metadata line
    reader = csv.DictReader(f)   # now reads the real header correctly
```

```bash
# awk (was NR>1 under the old format; now NR>2)
awk -F, 'NR>2' access-review.csv
```

```python
# pandas
df = pd.read_csv(path, skiprows=1)
```

A consumer that already treats the file as free-form text and looks for the
`# rbac_enforcement=` prefix, or that reads the `rbac_enforcement` field from
the sibling **JSON** export (`GET .../export` without `?format=csv`, or the
frozen campaign row's `rbac_enforcement` field), is unaffected either way.

### Executions-history PR 2 — `responses.execution_id` exact correlation

PR 2 of the executions-history ladder closes a forensic-data correctness
gap (UP-8) where two concurrent executions of the same definition to
overlapping agent sets could show each other's responses in the
Instructions → Executions detail drawer. Operators upgrading to a
release that includes PR 2 should expect the following:

**Schema migration v2 on `response_store`.** The migration adds an
`execution_id TEXT NOT NULL DEFAULT ''` column to the `responses` table
plus a partial index `idx_resp_execution_ts ON responses(execution_id,
timestamp) WHERE execution_id != ''`. The migration is automatic and
data-preserving — `MigrationRunner::run` wraps the ALTER + CREATE INDEX
in a single transaction. Pre-upgrade rows are NOT deleted; they receive
the empty-string sentinel value `''`. The migration is idempotent: a
pre-stamp probe at startup detects an already-altered DB and skips the
duplicate ALTER (mirrors the precedent at `instruction_store.cpp` v2).

Observable after upgrade:

```sql
SELECT execution_id, COUNT(*) FROM responses GROUP BY execution_id;
```

will show ALL pre-upgrade rows under the empty string `''`. This is
expected — there's no way to retroactively attribute pre-upgrade
responses to executions because the dispatch path didn't record the
linkage. The Executions drawer detects empty-`execution_id` rows and
falls back to the legacy timestamp-window-plus-agent-set join so they
render correctly without operator action. **No operator action
required** for the migration itself.

**Dispatch-path coverage gap (PR 2.x follow-ups).** Only executions
dispatched via `POST /api/instructions/:id/execute` (the dashboard's
Execute Instruction form goes through this path) get exact correlation
in PR 2. Three dispatch surfaces continue to write rows with
`execution_id=''` until follow-up PRs close them:

- **MCP `execute_instruction`** — agent dispatches issued through the
  MCP protocol.
- **Workflow steps** (`POST /api/workflows/:id/execute` step dispatch
  via `cmd_dispatch` callback) — multi-step workflows.
- **Scheduled / approval-triggered dispatches** — the dispatch path
  inside `schedule_engine` / approval-fired execution.
- **Reruns** (`/api/executions/:id/rerun`) — `create_rerun` creates
  the execution row but does not dispatch; the operator-triggered
  follow-up dispatch will be wired in PR 2.x.

For runs from these surfaces, the drawer's responses section uses the
legacy timestamp-window join. Cross-execution contamination (UP-8) is
still possible if two such runs overlap on the same definition + agent
set. Track via the executions-history follow-up issues.

**Mixed-mode detail drawer behaviour.** During an upgrade transition
window (executions in flight at restart time, or in-progress executions
that started pre-upgrade and finished post-upgrade), some responses for
a single execution may carry `execution_id=''` while others are
correctly tagged. The drawer prefers exact-correlation rows when they
exist and only falls back to the legacy join when zero exact rows are
returned — this means **mixed-mode runs may show only the
post-upgrade subset of their responses** in the drawer. Pre-upgrade
responses for those runs remain in the database and are queryable via
SQL; the upcoming admin backfill CLI (PR 2.1) will stamp them with
their correct execution_id once it ships.

**Server restart caveat.** The dispatch-time `command_id → execution_id`
mapping is held in memory inside `AgentServiceImpl`. If the server is
restarted while a command is in flight, the mapping is lost and any
agent responses arriving post-restart will be tagged `execution_id=''`
and use the legacy fallback. Avoid restarting the server during active
executions where possible, or accept that the affected runs will use
legacy correlation.

**Admin backfill (planned in PR 2.1, not in this release).** A
`yuzu-server admin backfill-responses` CLI is filed as a follow-up. It
will walk the executions table cross-store and stamp pre-upgrade
responses with their best-effort execution_id (timestamp + agent set
heuristic). Until it ships, pre-upgrade rows remain queryable via the
legacy fallback in the drawer; no operator action is required.

**Verifying the migration.** After upgrade, the server log should
contain `MigrationRunner: response_store migrated to v2`. To verify the
column directly:

```bash
sqlite3 /var/lib/yuzu/responses.db ".schema responses"
# Expected: execution_id TEXT NOT NULL DEFAULT ''
sqlite3 /var/lib/yuzu/responses.db ".schema idx_resp_execution_ts"
# Expected: CREATE INDEX idx_resp_execution_ts ON responses(...) WHERE execution_id != ''
```

### v0.12.0 — AuthDB persistent authentication (#618)

v0.12.0 replaces the in-memory + on-config-flush authentication model
with a SQLite-backed `auth.db` that holds user accounts, sessions, and
enrollment tokens.

**First boot after upgrade:**

- The server probes `--data-dir` for `auth.db`. If absent, it creates
  the file with mode `0600` (Linux) or restricted ACL (Windows), runs
  the initial schema migration via `MigrationRunner`, then seeds users
  from `yuzu-server.cfg`. Subsequent boots read from `auth.db`
  directly; the config file is no longer the live source of truth.
- The seed is one-shot. Editing `yuzu-server.cfg` after first boot
  does NOT re-seed users into `auth.db` — use the dashboard or
  `POST /api/settings/users` instead.
- Existing in-flight sessions are NOT preserved across the upgrade
  (sessions live in memory before this release; `auth.db` starts fresh
  on first boot). Operators must log in again.

**`role` parameter ignored on `POST /api/settings/users`.** New users
are always created as `user` (security finding C1). To assign or
change a role, use the dedicated `POST
/api/settings/users/{username}/role` endpoint introduced in v0.12.0
(see [REST API → Settings → User Management](rest-api.md#settings--user-management)).
The dashboard exposes a **Change Role** button on each user row that
calls the new endpoint.

**Live drawer updates via SSE.** The Executions tab opens an
`EventSource` to `/sse/executions/{id}` for in-progress runs. Reverse
proxies in the request path must NOT buffer SSE — the server emits
`X-Accel-Buffering: no` and `Cache-Control: no-cache` but a poorly-
configured proxy can still chunk the stream. Verify with
`curl -N https://<server>/sse/executions/<id>` from inside your
network if the drawer freezes mid-execution.

**`LimitNOFILE=65536` on systemd units.** v0.12.0 raises the systemd
file-descriptor limit from the default 1024 to 65536. SSE
connections + agent gRPC streams + SQLite WAL handles can saturate
the default soft limit on busy fleets. The new value matches Docker
compose's `ulimits.nofile` so containerised and bare-metal deployments
behave identically.

**Restart-loop guard.** `StartLimitIntervalSec=60` +
`StartLimitBurst=3` in the systemd `[Unit]` section so a corrupt
`auth.db` failing the integrity check at startup puts the unit
cleanly into `failed` instead of spinning. Recovery procedure:
[`docs/ops-runbooks/auth-db-recovery.md`](../ops-runbooks/auth-db-recovery.md).

**Rollback to a pre-AuthDB release** (only if you have not yet
written user state via the new dashboard):

1. Stop the v0.12.0 server.
2. Move `auth.db` aside (`mv auth.db auth.db.v0.12.0`).
3. Restore `yuzu-server.cfg` from your pre-upgrade backup.
4. Reinstall the prior release binary.
5. Start the server. It reads `yuzu-server.cfg` as before.

If you HAVE written user state via v0.12.0's dashboard, that state
is in `auth.db` only — rolling back loses it. Export users via
`GET /api/v1/settings/users` first if rollback is required.

### v0.12.0 — Guardian PR 2

Guardian PR 2 ships the Guaranteed State control plane + agent skeleton. Two items require operator awareness on upgrade:

**Stale `*:Push` RBAC grants on deployments that ran pre-hardening Guardian PR 2 code.** Between commits `7c83911` and `1f39401`, the RBAC seed granted the `Push` operation to `Administrator` and `ITServiceOwner` on **every** securable type, not just `GuaranteedState`. The H-4 fix (commit `21c0ba4`, hardening round 2) restricted the seed to `GuaranteedState` only going forward — but because `seed_defaults()` uses `INSERT OR IGNORE`, the stale cross-type grants already written to `role_permissions` are not removed on upgrade. These grants are semantically inert today (only the Guardian REST handlers consult `Push`), but become a latent privilege for any future release that adds a non-Guardian handler checking `perm_fn(..., "Push")`.

Manual remediation until the auto-migration in issue #485 lands. **Run each step in order:**

1. **Back up the RBAC database first.** Destructive SQL with no rollback.

   ```bash
   docker exec yuzu-server cp /var/lib/yuzu/rbac.db /var/lib/yuzu/rbac.db.bak.$(date +%Y%m%d)
   # or for a systemd install:
   cp /var/lib/yuzu/rbac.db /var/lib/yuzu/rbac.db.bak.$(date +%Y%m%d)
   ```

2. **Preview the rows that will be deleted.** This should return only `Administrator` and `ITServiceOwner` rows on a fresh Guardian PR 2 upgrade. If it returns rows for any other principal_id, you have custom RBAC grants that the bulk `DELETE` below would silently wipe — in that case stop and prune by hand.

   ```bash
   docker exec -i yuzu-server sqlite3 /var/lib/yuzu/rbac.db \
     "SELECT principal_id, securable_type FROM role_permissions \
       WHERE operation = 'Push' AND securable_type != 'GuaranteedState' \
       ORDER BY principal_id, securable_type;"
   ```

3. **Delete the stale grants.** Scoped to the two seeded roles so custom grants are left alone:

   ```bash
   docker exec -i yuzu-server sqlite3 /var/lib/yuzu/rbac.db \
     "DELETE FROM role_permissions \
       WHERE operation = 'Push' \
         AND securable_type != 'GuaranteedState' \
         AND principal_id IN ('Administrator', 'ITServiceOwner');"
   ```

4. **Confirm cleanup:** re-run the preview query from step 2 — zero rows expected.

Safe on fresh installs (no matching rows). If you are upgrading **from** a v0.11.x release directly **to** v0.12.0 or later, skip this entire sub-section — your RBAC database never carried the stale grants.

**Retention changes take effect on restart, not on runtime PUT.** BL-2 wired `--guardian-event-retention-days` (default 30) through `RuntimeConfigStore` + `PUT /api/config/guardian_event_retention_days`, matching the existing `response_retention_days` and `audit_retention_days` pattern. However, all three retention-bearing stores (`AuditStore`, `ResponseStore`, `GuaranteedStateStore`) capture their retention value at construction time and never re-read it — the runtime PUT mutates `cfg_` and `RuntimeConfigStore` but the running reaper continues using the startup value. An operator who PUTs a new retention value sees `200 {"applied": true}` but the store behaviour does not change until the next server restart. This is a systemic limitation shared across all three stores, not a Guardian-specific bug; it is tracked as issue #483.

**Runtime config PUT now rejects non-numeric and negative integer values with HTTP 400.** Hardening round 4 (UP-R5) added `std::from_chars` validation to `PUT /api/config/<key>` for `heartbeat_timeout`, `response_retention_days`, `audit_retention_days`, and `guardian_event_retention_days`. The previous handler silently wrote invalid strings to `RuntimeConfigStore` and swallowed the `stoi` error, leaving `cfg_` unchanged. If your automation relied on setting retention to a **negative** value (e.g., `"-1"`) to disable retention — which the store then treated as "never reap" via the `<= 0` sentinel — that automation will now receive `400 {"error":{"code":400,"message":"value must be a non-negative integer"}}`. Use `"0"` instead **only for `guardian_event_retention_days`**, where it preserves the disable-retention semantic and passes validation. For `heartbeat_timeout`, `response_retention_days` and `audit_retention_days` the store applies its own `> 0` check *after* the route's, so `"0"` is also rejected - with a different, bare-shaped body, `{"error":"value must be a positive integer"}`. There is no supported way to disable retention for those three through this endpoint. Automation that previously set non-numeric strings (anything other than a base-10 integer) was silently a no-op before this release — the 400 now surfaces the configuration error that had been hidden.

### v0.12.0 — A3 UX ladder (#620, #622, #624)

Three operator-visible behaviour changes ship in the v0.12.0 A3 ladder. None require code changes on the operator side, but two of them require **action if you maintain a local compose override**:

**1. Container healthchecks now pass (#622).** The shipped `docker-compose.uat.yml` healthcheck blocks were updated to use tools available in each runtime image (`bash` + `/dev/tcp` for the server; busybox `wget --spider` for the gateway). After upgrade, `docker compose ps` reports `(healthy)` instead of `(unhealthy)`.

> **If you maintain a local copy of the compose file** (e.g. `docker-compose.local.yml` or a pinned vendored copy), your override still uses the broken pre-fix healthcheck pattern and will continue showing `(unhealthy)` until you sync the change. Replace your server-service healthcheck stanza with:
>
> ```yaml
>     healthcheck:
>       test:
>         - "CMD"
>         - "bash"
>         - "-c"
>         - "exec 3<>/dev/tcp/localhost/8080 && printf 'GET /livez HTTP/1.0\\r\\nHost: localhost\\r\\n\\r\\n' >&3 && grep -q '200 OK' <&3 ; rc=$? ; exec 3>&- ; exit $rc"
> ```
>
> And the gateway-service healthcheck stanza with:
>
> ```yaml
>     healthcheck:
>       test: ["CMD", "wget", "--spider", "-q", "http://localhost:8081/healthz"]
> ```

**2. `/api/health` is restored as an alias of `/health` (#620).** The pre-#401 endpoint path is back. Monitoring integrations that point at `/api/health` work without reconfiguration; both URLs serve identical JSON. Both are exempt from rate limiting (a follow-up hardening over the bare `/health` behaviour). For load-balancer probes that should drain in-flight traffic before stopping, continue using `/readyz` — `/health` and `/api/health` are intentionally not draining-aware (Kubernetes pattern: liveness/health probes are not draining-aware).

**3. File-logger boot messages are now quieter (#624).** The previous `WARN: Could not create log directory /var/log/yuzu` + `ERROR: file logger setup failed` pair on every container boot is replaced by a single INFO-level line when the default path cannot be created. The Docker server image now pre-creates `/var/log/yuzu` (mode 0750, owned by `yuzu`) so the path is writable out of the box. **If your monitoring previously alerted on the WARN/ERROR lines as a misconfig signal, those signals will no longer fire** — the failure mode is now a single INFO line. Operators who require explicit on-disk logs should pass `--log-file <path>`; explicit-path failures still log at ERROR and are not silently degraded.

### `quarantine` plugin: reporting is now more conservative (Wave-2 argv migration)

The `quarantine` plugin's Windows/Linux/macOS `netsh`/`iptables`/`pfctl` invocations were migrated off shell-outs onto a bounded argv runner. Alongside the mechanism change, two reporting bugs were fixed: a Linux chain-flush could previously be miscounted as an applied containment rule (`status|quarantined|rules_applied|1` reported with zero rules actually installed), and macOS whitelist mutations could silently proceed on a failed prerequisite read or report success despite `pfctl -e` failing to enable pf.

**If your automation alerts on `status|failed`/`status|release_uncertain`/`status|update_uncertain` from `quarantine` actions, you may see these fire more often after upgrading** — this is expected. Nothing got more broken; the plugin's failure reporting simply got more honest about cases it previously reported as clean success. No action is required beyond expecting the change.

## Rollback

If an upgrade causes issues:

1. Stop the new version
2. Restore the backed-up `.db` and `.cfg` files
3. Start the previous version binary

**Important:** Rolling back after a schema migration requires restoring the database files from backup. The old binary cannot read the new schema.

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| Server won't start after upgrade | Schema migration failure | Check logs, restore backup, report issue |
| Agents can't connect | Protocol version mismatch | Ensure server was upgraded first |
| Dashboard shows errors | Browser cache | Clear browser cache, hard refresh |
| Gateway disconnects | Version mismatch with server | Upgrade gateway to match server version |
| Slow startup | Large database migration | Normal for first start; wait for migration to complete |
