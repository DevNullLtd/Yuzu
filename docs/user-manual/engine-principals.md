# Engine Principals

Engine principals are the durable identities behind autonomous use-case-engine
modules (ADR-1005 item 2b) — a third principal class alongside human users and
human-created API tokens. Each engine principal has a named responsible human
owner, a grant justification captured at creation, and a required
`internal`/`external` classification, and it cannot be granted the admin
role or any other built-in role. A custom role that grants every permission is
not refused when it is assigned; the no-admin audit reports it afterwards.

This page is an operator walkthrough. Full API reference:
[REST API — Engine Principals](rest-api.md#engine-principals);
[MCP tools 55–63](mcp.md#available-tools); design reference:
`docs/auth-engine-principals-design.md`; architecture summary:
`docs/auth-architecture.md` "Engine principals & delegation".

## Who this is for

Use engine principals for a first-party or third-party autonomous module that
needs its own credential, distinct from any human operator's token — for
example a future use-case-engine sync job. Do **not** use an engine principal
as a substitute for a normal service-scoped API token held by a human-run
automation pipeline; engine credentials are hard-locked to MCP tier
`readonly` and structurally barred from the admin role, which is the wrong
shape for anything that needs to execute or approve on a human's behalf.

## Before you start

Every mutating operation on this surface requires:

- An **admin session** with **MFA step-up** (REST) or the **`supervised`**
  MCP tier plus **maker-checker approval** (an approver who is not the
  submitter) for the six mutating MCP tools.
- The `owner_username` (and, for a transfer, the `new_owner`) must already
  exist as a real Yuzu user — creation and transfer both fail closed
  (`400`) against an unknown username.

**A structural rule with no exception:** a caller whose *own* session is
itself engine-classed can never touch this surface at all, on either
transport — not even to read. REST and all 9 MCP tools carry the same
denial belt.

## Walkthrough: create, mint, rotate, confirm, transfer, revoke

### 1. Create the principal

Dashboard: Settings → **Engine Principals** → fill in Slug, Display Name,
Owner, Classification, Justification → Create. When the list or an engine principal's credentials cannot be read (for example while the database connection pool is exhausted), the panel says so: an "unavailable" notice replaces the table, or the Active Creds cell shows "unavailable" and the row offers neither Mint nor Rotate. Reload once the store recovers.

REST:

```bash
curl -sk -X POST https://localhost:8080/api/v1/engine-principals \
  -H "Origin: https://localhost:8080" \
  -H "Cookie: $COOKIE" -H 'Content-Type: application/json' \
  -d '{
    "slug": "vuln-uce",
    "display_name": "Vuln UCE",
    "owner_username": "alice",
    "classification": "internal",
    "justification": "First-party vulnerability-management use-case engine module"
  }'
```

The server derives `principal_id = "engine:vuln-uce"`. `classification` has
no default — an empty or unrecognized value is rejected outright, so an
engine principal can never exist in an unclassified state.

### 2. Mint the first credential

The principal has no credential yet. Mint one (dashboard: **Mint** button;
REST: `POST .../credentials`):

```bash
curl -sk -X POST https://localhost:8080/api/v1/engine-principals/engine:vuln-uce/credentials \
  -H "Origin: https://localhost:8080" \
  -H "Cookie: $COOKIE" -H 'Content-Type: application/json' \
  -d '{ "ttl_days": 90 }'
```

The response carries the raw secret **exactly once**, under
`Cache-Control: no-store` — copy it immediately into the consuming module's
secret store. It cannot be retrieved again; only rotated or revoked. If the
server cannot read the token store to check that the principal has no
credential yet, it answers `503` with `Retry-After: 2` and mints nothing, so
retrying after that `503` is safe. The MCP tool `mint_engine_credential` does the
same (a retryable error with a `retry_after_ms` hint, nothing minted). If the
credential is minted but the server then cannot read it back, it answers `503`
with the secret withheld and the audit row `engine_principal.credential.mint`
with `result=partial`; the credential exists but its secret was never shown, so
do **not** retry the mint (that is a `409`): rotate it to obtain a secret.
The same `503` and `partial` row apply when the read-back **answers but finds no
active credential** (the new credential was revoked out of band between the
insert and the read-back): the secret is withheld rather than delivered with an
empty `token_id`. Check the principal's credentials, and rotate only if one is
listed. Mint does not take a lock between the check and the insert, so two mint
requests in flight at the same moment can both pass the check. Send them one at
a time.

### 3. Rotate the credential (overlap-pair model)

Design §7's overlap-pair rotation is the only supported rotation shape — there
is no "replace in place." Rotating mints a **successor** credential while the
existing (**predecessor**) credential stays valid for an overlap window, so
the consuming module has time to pick up the new secret without a hard cutover:

```bash
curl -sk -X POST https://localhost:8080/api/v1/engine-principals/engine:vuln-uce/credentials/rotate \
  -H "Origin: https://localhost:8080" \
  -H "Cookie: $COOKIE" -H 'Content-Type: application/json' \
  -d '{ "overlap_secs": 604800 }'
```

- At most **two** active credentials exist for a principal at any time.
- The overlap window has a **24-hour floor** — a shorter request is rejected
  outright, never silently rounded up.
- A same-caller retry within a short (~120-second) grace window after the
  original mint **re-serves the same successor secret** rather than erroring
  or minting a second successor — safe to retry a dropped response. Every
  successful return, original or replay, is independently audited under
  `engine_principal.credential.reveal`.
- If the rotation commits but the server then cannot read the new credential
  back to build the response, it answers `503` with `Retry-After: 2` and
  **withholds the secret**; the audit row is
  `engine_principal.credential.rotate` with `result=partial`, with no reveal
  row. Retry inside the same ~120-second grace window, as the same operator
  and against the same server replica, to receive the same successor secret.
  The grace window is held in that replica's memory: after a restart, on a
  different replica, or once the window has ended, the retry is a `409`. The
  MCP tool `rotate_engine_credential` behaves the same way (a retryable error,
  secret withheld, `result=partial`). A `result=partial` row is the operator
  signal that a successor exists whose secret was never delivered.
- If the rotation committed and the read-back **answered but found no linked
  successor** (the successor was revoked or confirmed out of band in between),
  the response is also `503` with the secret withheld and `result=partial`, but
  with **no retry hint**: there is no pending pair to re-serve, and an automatic
  retry would perform a *new* rotation you did not ask for. The message says
  "A successor may exist; inspect the principal's credentials
  (`GET /api/v1/engine-principals/{id}`), then rotate again if needed." Do that,
  then rotate again only if the principal needs a new credential. The MCP tool
  `rotate_engine_credential` answers the same way, also without a retry hint.
- **If the secret is lost** (the grace window passed, or the replica changed),
  the pair is stuck with a successor nobody holds. Recover in three steps:
  1. Find the successor with `GET /api/v1/engine-principals/{id}`. In its
     `active_credentials` list a stuck pair is two credentials sharing a
     `rotation_group`; the successor is the one whose `overlap_expires_at` is
     `0` while the predecessor's is non-zero. That read fails closed: when the
     token store cannot answer, the route returns `503` with `Retry-After: 2`
     instead of an empty `active_credentials` list, so repeat it after the `503`
     clears.
     (`GET /api/v1/tokens` does not list it: that route is scoped to the
     caller's own tokens, and an engine credential is owned by the engine
     principal.)
  2. Revoke the successor with `DELETE /api/v1/tokens/{token_id}`. This is a
     REST call only (the MCP tools have no per-credential revoke). It needs
     `ApiToken:Delete`, a fresh MFA step-up, and an **effective administrator**,
     because only the token's owner or an administrator may revoke it and the
     owner here is the engine principal, not a person. Any other caller gets
     `404 token not found`.
  3. Rotate again. After the successor is revoked the predecessor is the sole
     credential, and rotating it starts a fresh pair.

  Do **not** revoke only the predecessor: that leaves the principal holding a
  single credential whose secret no one has. Do **not** revoke the principal
  itself (`DELETE /api/v1/engine-principals/{id}`) as a recovery step: that is
  terminal and destroys the identity and every credential.
- If the consuming module updates the secret and you never call `confirm`
  (next step), a **60-second background sweep** enforces predecessor
  auto-revoke on your behalf, with this SLA: **a predecessor is revoked
  within one 60-second tick of its overlap window elapsing; on the first
  occurrence of a given clock-guard anomaly the tick declines instead and
  revocation defers to the next tick (roughly 120 seconds total), after
  which an identical anomaly drains normally on the following tick; every
  decline is counted and logged — a fresh deployment's first-ever bootstrap
  decline (no durable clock reading yet) increments
  `yuzu_rotation_sweep_bootstrap_declines_total`, any other decline (an
  implausible reading, or a big step since the last accepted tick)
  increments `yuzu_rotation_sweep_declined_total`; the two are deliberately
  separate series (see [metrics.md](metrics.md#rotation-sweep-clock-guard-metrics-2964)).**
  A big-step decline is **not necessarily a clock fault** — the sweep's
  3600s big-step threshold is crossed just as readily by a multi-tick gap
  with a perfectly correct clock (a maintenance window, a database
  failover, an instance left off overnight) as by an actual clock jump.
  One case is not "eventually" but **never**, by design, until an operator
  acts: **the successor was never presented at all** — the sweep leaves BOTH
  credentials active indefinitely rather than revoke your only working
  credential out from under you (a dropped rotate response, or simply never
  picking up the new secret, must not end in zero usable credentials). A
  **sustained clock anomaly is NOT this case**, even though it sounds like
  it should be: the guard suppresses only a *repeat of the identical*
  anomaly (the fact-set dedup rule) and drains on the very next tick once it
  does, so a clock fault that settles on one anomaly shape — even
  indefinitely — costs at most the one extra declined tick already described
  above, and revocation then proceeds on schedule against the (still bad)
  clock reading; do not read this SLA as "credentials are held safe for the
  duration of a clock incident". The genuinely open-ended never-until-an-
  operator-acts cases are (a) a clock fault that keeps changing shape tick to
  tick (each distinct fact set declines fresh, so dedup never gets a repeat
  to suppress) and (b) a **store-wide-lock fault** — every replica losing the
  sweep's advisory lock to a wedged holder — neither of which an operator can
  tell apart from "one declined tick" using this page alone, which is
  exactly what `docs/ops-runbooks/rotation-sweep-clock-guard.md` and the
  `YuzuRotationSweepNotRunning` alert exist to surface. The sweep separately
  warns (an operational signal, not a security alert) whenever the
  *successor* looks unused — once as its own window nears expiry, and once
  more on crossing into the elapsed state if it is still unused (that row
  and its metric fire once per pair per state, process-local — a restart
  re-emits once; the underlying log line, by contrast, repeats every tick
  once elapsed) — a sign the new secret was never actually picked up; once
  that warning has fired for the elapsed state, do not assume the sweep will
  eventually clean it up (it will not — see the "never presented" case
  above) — either confirm once the successor genuinely is in use, or revoke
  the *specific* credential you no longer trust (the successor, if its secret
  was never picked up) via
  `DELETE /api/v1/tokens/{token_id}` (never
  `DELETE /api/v1/engine-principals/{id}` — see step 4's callout below for
  why).

### 4. Confirm the rotation (optional but recommended)

Once the consuming module has verifiably picked up the new secret, close the
loop explicitly instead of waiting for the sweep:

```bash
curl -sk -X POST https://localhost:8080/api/v1/engine-principals/engine:vuln-uce/credentials/confirm \
  -H "Origin: https://localhost:8080" \
  -H "Cookie: $COOKIE" \
  -H "Content-Type: application/json" \
  -d '{"token_id": "<token_id from the rotate response>", "secret": "<the raw successor secret from the rotate response>"}'
```

This revokes the predecessor immediately and promotes the successor to the
principal's sole active credential. `confirm` is a **separate attestation**
from the `rotate` reveal — the server never infers "installed" from "the
rotate call returned 200." Confirm now requires **proof of possession** of
the successor: alongside the `token_id`, you must present the raw `secret`
the rotate response returned, which the server verifies against the stored
hash (a missing/empty `secret` is a `400`; a wrong one is a `403` and
changes nothing). The `token_id` still pins the confirm to that exact
rotation, so a blind retry of an old confirm can never resolve a **later**
rotation early (a stale or mismatched id gets a `409` and changes nothing).
Because possession of the secret is required, a lost rotate response can no
longer be used to confirm — revoke the unknown successor and rotate again
instead (see the callout below).

`confirm`'s check that you're the same operator who called `rotate` is
stored durably, not just in memory, so a server restart no longer blocks
confirming an in-flight rotation. The one exception: a rotation already in
flight *before* this durability guarantee was deployed has no durable
record of who initiated it, and a restart still leaves it permanently
unconfirmable (fails closed rather than accepting just anyone) — confirm
before restarting during an upgrade if you can.

**If you can't, do nothing — the 60-second background sweep (step 3) still
resolves the pair on its own, `confirm` or no `confirm`.** Once the
successor has been presented, the sweep auto-revokes the predecessor at the
overlap window's end exactly as if you had confirmed; if the successor was
never presented, the sweep deliberately leaves **both** credentials active
rather than revoke your only working one. Neither outcome ends at zero
usable credentials — what's lost by skipping `confirm` here is the
attestation record, not access.

**Do not run `DELETE /api/v1/engine-principals/{id}`** ("Revoke (terminal)",
step 6 below) to resolve an unconfirmable pair — that revokes *both* active
credentials and permanently flips the principal itself to `revoked`,
destroying the working credential along with the one you meant to discard.
There is no per-credential revoke among the engine-principal routes above.
If you must resolve the pair by hand rather than wait for the sweep, revoke
the *specific* credential you no longer trust instead: an engine credential
is an ordinary API token row, so `DELETE /api/v1/tokens/{token_id}` (an
admin caller may revoke any token, not just one they created — see
`docs/user-manual/rest-api.md` "`DELETE /api/v1/tokens/{token_id}`") works
on it, then rotate again once you're down to one active credential.

If you replay a `confirm` **after it already succeeded** — a dropped `200`, a
double-submit, or a client racing the auto-revoke sweep — you get a *terminal*
`409` (`rotation already confirmed` / `no rotation in flight ... already the
sole active credential`), not a retryable `503`. Treat it as done: the rotation
is resolved and there is nothing left to confirm. Rotate again only if you
genuinely need a fresh credential. (The one case that stays `503`-retryable is
a genuine store hiccup — an empty read, lock contention, or a persist failure —
where retrying is the right move.)

### 5. Transfer ownership

Ownership transfer is **admin-forced** — it does not require the outgoing
owner's cooperation, so an account under termination-for-cause cannot use
engine-principal ownership as a lever to stall its own deprovisioning:

```bash
curl -sk -X POST https://localhost:8080/api/v1/engine-principals/engine:vuln-uce/transfer-owner \
  -H "Origin: https://localhost:8080" \
  -H "Cookie: $COOKIE" -H 'Content-Type: application/json' \
  -d '{ "new_owner": "bob" }'
```

### 6. Revoke (terminal)

Revoke is **terminal and irreversible** — there is no un-revoke. Recovery from
a compromised or retired principal is to create a **successor** principal and
reference the old one via `superseded_by`:

```bash
curl -sk -X DELETE https://localhost:8080/api/v1/engine-principals/engine:vuln-uce \
  -H "Origin: https://localhost:8080" \
  -H "Cookie: $COOKIE" -H 'Content-Type: application/json' \
  -d '{ "superseded_by": "engine:vuln-uce-2" }'
```

Every active credential is revoked **first**, then the identity itself flips
to `revoked` — a caller can never observe a revoked identity with a
still-valid credential. Calling this again on an already-revoked principal is
a no-op success, not an error.

## The owner-delete interlock (two-mode enforcement)

A user who owns an active engine principal must not be silently removed —
otherwise the principal's audit trail loses its named responsible human. This
is enforced in two modes, chosen by whether an operator is in the loop:

- **Interactive dashboard delete → prevention (`409`).** Deleting such a user
  from Settings → Users is blocked with a `409` and a toast pointing at the
  transfer-owner surface above. This is fail-**closed**: if the engine-principal
  store cannot even be reached to check, the delete is blocked too, never
  allowed through on "couldn't verify." An admin is present and can transfer
  ownership first, so prevention is the right control.

- **Automated SCIM deprovision → detection (audit + metric, never blocked).**
  SCIM-driven deprovisioning (an IdP deactivating or deleting a user, via
  `PATCH`/`PUT active:false` or `DELETE`) is a **compliance-mandated termination
  flow** (SOC 2 CC6.8) with no operator in the loop. Refusing it would leave a
  terminated employee's account **active** — a worse control failure — and
  auto-revoking their engine principals is rejected because revoke is terminal
  and irreversible (an IdP flap would destroy machine identities). So the
  deprovision **always succeeds**, but if the departing user owned active engine
  principals (or ownership can't be verified), the server emits a high-signal
  audit `engine_principal.owner_deprovisioned` and increments
  `yuzu_engine_principal_owner_deprovisioned_total` so an admin can reassign
  ownership out of band. The orphaned principal keeps authenticating on its own
  credential — it never derived authority from its owner — so the departed user
  gains nothing. Alert on that metric and transfer ownership promptly when it
  fires.

## The no-admin auditor

`GET /api/v1/engine-principals/audit/no-admin` (REST) and `audit_engine_no_admin`
(MCP, available on every MCP tier) are an independently-runnable **check** of
the "no admin" rule across every engine principal, rather than a claim about the
write-path guard that creates and grants them. They read every grant held by an
`engine:` id from the grant table, with each role's permissions, and report
three kinds of detected grant: a literal `admin`/`Administrator` role
(`admin_role`), a role flagged `is_system` (`system_role`), and a
`wildcard_grant`, meaning a role (or, with an empty `role`, the union of a
principal's roles) that allows every `securable x operation` pair of the grid as
it is at run time. Grants are read by principal id, whatever their principal
type, so a grant of type `user` on an `engine:` id is reported too, and `role`
carries the role's name. Only `admin_role` and `system_role` mean the
assignment check was bypassed; a `wildcard_grant` is permitted by design and is
reported for review (the Tokens page words the two differently).

The MCP tool also takes `include_revoked` (default `true`, MCP only). `false`
is a different report, not a subset of the default run. It skips principals the
engine-principal roster lists as **revoked**, and it also reports
`orphan_grant` for every `engine:` grant whose principal has no roster row at
all (a stale or out-of-band grant that a walk over the roster would hide). The
default run and the REST route never report `orphan_grant`, so a grant of a
harmless role to a principal with no roster row is `ok:true` there and a
finding on the narrowed run. Use the default run for the full-population
answer. The success audit row records `scope=active` for a narrowed run and
`scope=all` otherwise, so a narrowed `violations=0` is not mistaken for a
full-population result.

**What assignment refuses, and what it does not.** Assigning a role to an engine
principal refuses the `admin` and `Administrator` role names and every built-in
(`is_system`) role. It does **not** refuse a custom role that covers the whole
grid: that is permitted by design (maintainer ruling 2026-10-23, #2485) and is
**detected afterwards** by this auditor. Role permissions can also be edited
after the role was assigned, which is why the check is run against live data.

```bash
curl -sk https://localhost:8080/api/v1/engine-principals/audit/no-admin \
  -H "Cookie: $COOKIE"
```

```json
{ "data": { "ok": true, "violations": [] } }
```

What `ok:true` means, and what it does not:

- It means no role held by an engine principal, and no engine principal's union
  of roles, allows every pair of the current grid **at the moment of the run**.
  A role that grants every pair but one is **not** reported, and a role that
  covered the grid before an upgrade added a new securable stops being reported
  until it is granted the new pair. `deny` rows are ignored (over-reporting is
  the safe direction).
- It is a point-in-time, pull-only check. Nothing runs it on a schedule and
  nothing alerts on a `wildcard_grant`; the cadence is the operator's. Each run
  writes an `engine_principal.audit.no_admin` audit row
  (`violations=N scope=all|active`, then up to ten detected
  `principal_id:reason` pairs), and those rows are the evidence the control
  operated. The Tokens page also runs the check incidentally, in the browser,
  whenever a viewer who holds `AuditLog:Read` loads the principals panel; that
  is not a schedule and not a control (other viewers see a note that the check
  needs `AuditLog:Read`, and a deployment nobody opens in a browser never
  triggers it). A success row whose write was dropped is signalled only by
  `Sec-Audit-Failed` on REST (the MCP tool gives no signal). A period with no
  rows is therefore not evidence that the check ran or that it passed; absence
  of rows shows at most that no recorded run exists. The grants, the roles and the role permissions are three separate
  reads, not one snapshot: a role granted or edited between them is picked up by
  the next run. Run it after every role assignment to an engine principal
  and periodically as part of a machine-identity access review.
- It fails closed. If any read it depends on cannot be answered (the grants,
  the roles, the role permissions, or the RBAC reference data), the route returns
  `503` ("rbac resolution unavailable - cannot verify", `Retry-After: 2`; the MCP
  tool returns a retryable error with `retry_after_ms`), with no partial list and
  an `engine_principal.audit.no_admin` row with `result=failure`. Treat that as
  "run again," never as "clean." This auditor is gated on `AuditLog:Read`, not
  `Security`, deliberately (with RBAC enabled; admin-only while RBAC is off,
  #5771): a read-only auditor role can run it without holding engine-principal
  write access.

## Per-principal quota cap (PR 4.4)

Every engine principal is subject to a per-principal quota cap enforced at
the server's single pre-routing chokepoint — on both REST and MCP traffic,
before the request reaches any route handler. Human, device-agent, and
anonymous traffic is never gated by this cap. This is the minimum
per-principal cap required by the #1973 production interlock: no engine
principal may be enabled in production until it exists.

### Layered limits for engine principals

An engine-principal request can be rejected by up to four independent caps,
evaluated in the order (a), (c), (d), (b): (a), (c) and (d) run in the server's
pre-routing step, while (b) runs later, in the MCP `initialize` handler, and
applies only there (the others apply to REST routes and `/mcp/` alike). The
letters name the rows, not the order:

| # | Cap | Scope | Error / code | Notes |
|---|---|---|---|---|
| a | Per-IP rate limiter (existing) | Source IP | HTTP `429` | Applies to every caller, not just engine principals; checked before any principal is resolved. |
| b | MCP session cap (8 concurrent sessions) | MCP session lifecycle, checked on `initialize` | JSON-RPC `-32010` / HTTP `429` | Rejects a **new session**, never evicts a live one. |
| c | Per-principal in-flight concurrency (16, PR 4.4) | Per engine principal, every REST and `/mcp/` request | HTTP `429` with the A4 envelope on REST; JSON-RPC `-32010` / HTTP `429` on MCP | This page's quota cap, concurrency dimension. |
| d | Per-principal rate (20 rps, PR 4.4) | Per engine principal, every REST and `/mcp/` request | HTTP `429` with the A4 envelope on REST; JSON-RPC `-32010` / HTTP `429` on MCP | This page's quota cap, rate dimension. |

(a) is the only dimension that also applies to non-engine traffic.
(b) is distinct from (c)/(d): it gates `initialize` only, on the *number of
open sessions*, while (c)/(d) gate *every* REST and `/mcp/` request on
in-flight count and request rate regardless of session state. The quota runs
once the engine's credential has resolved: while the database cannot answer, the
pre-routing authentication resolves no credential and the request is refused
`401` `unauthorized` before the quota is consulted. **(b) and (c)/(d) share the
same JSON-RPC error code `-32010`** — disambiguate by `error.message`
("session limit" vs "per-principal rate/concurrency cap exceeded") and by
`retry_after_ms` (always `null` for (b); non-null for (c)/(d) — see
[MCP — Troubleshooting](mcp.md#-32010-session-limit-reached-http-429)).

Two independent dimensions are enforced behind one decision:

| Dimension | Flag | Env var | Default | What it limits |
|---|---|---|---|---|
| Concurrency | `--principal-max-concurrency` | `YUZU_PRINCIPAL_MAX_CONCURRENCY` | `16` | In-flight requests for one engine principal at any instant. |
| Rate | `--principal-rate-limit` | `YUZU_PRINCIPAL_RATE_LIMIT` | `20.0` (requests/second) | Sustained request rate for one engine principal (token bucket; burst capacity is 2x the configured rate). |

Exceeding either cap returns HTTP `429` with a `Retry-After` header — the A4
error envelope on REST, a JSON-RPC `id: null` error (code `-32010`) on MCP;
see [REST API — Per-principal quota cap](rest-api.md#json-envelope) and
[MCP — Troubleshooting](mcp.md#-32010-session-limit-reached-http-429) for the
exact wire shapes. **Streaming/SSE requests take a concurrency slot held for
the stream's lifetime (released when the stream ends), plus the rate
debit — the same two caps as any other engine request** (UP-1; a hardening
fix — an earlier revision of this doc, and of the primitive itself, treated
streaming as rate-capped-only and concurrency-exempt, which left an engine
principal able to open an unbounded number of concurrent streams).

**Forward guard (track 2f).** When MCP Streamable-HTTP `GET`/`POST` gains a
live SSE stream (today `GET /mcp/v1/` is a `405` placeholder — see
[MCP — Streamable HTTP sessions](mcp.md#streamable-http-sessions)), that
handler MUST adopt the pending concurrency slot into the stream exactly like
the three routes already covered by this cap, or it silently reintroduces
the UP-1 gap for MCP engine principals specifically — the surface this cap
exists to protect.

**Tuning guidance:** the defaults (16 concurrent, 20/s) are conservative
starting points for a single autonomous module; raise
`--principal-max-concurrency` for an engine that legitimately fans out many
parallel reads, or raise `--principal-rate-limit` for a tight polling loop.
Both flags are server-wide (they apply to every engine principal on this
server instance, not per-principal-id tuning) — there is no per-principal
override in PR 4.4.

**Per-instance caveat.** The cap lives in one server process's memory. If you
run multiple server replicas behind a load balancer, each replica enforces
the cap independently — an engine principal whose traffic is spread across
N replicas effectively gets N x the configured cap, not one fleet-wide
budget. A durable, cross-instance quota (a shared store keyed by principal)
is a Phase-8 follow-up; until then, size the caps assuming per-replica
enforcement, or pin an engine principal's traffic to a single replica if a
tighter fleet-wide bound matters.

A quota rejection is observed via
`yuzu_server_principal_quota_exhausted_total{side,limit}` (paired with the
admits counter `yuzu_server_principal_quota_admits_total{side}` so the
exhaustion rate is computable — see
[Metrics](metrics.md#per-principal-quota-metric-pr-44-adr-1005-class-engine-principals))
— it is metric-only and does **not** write an audit row (see
[Audit Log](audit-log.md#logged-actions)); a quota rejection is a
high-frequency operational event, not a lifecycle action against the
principal.

**Deferred to Phase 5:** the quota primitive only debits the engine
principal's own budget today. Once delegation (RFC-8693-style) ships, a
delegated call will need to debit both the engine principal's side and the
delegating operator's side, and delegation-artifact issuance itself will
need its own rate cap — both are out of scope for PR 4.4.

## Audit trail

Every lifecycle action on this surface is recorded under an
`engine_principal.*` audit verb — see the
[Audit Log reference](audit-log.md#logged-actions) for the full table,
including the two verbs (`engine_principal.rotation.auto_revoke`,
`engine_principal.rotation.successor_unused`) emitted by the background
rotation sweep rather than an operator call.
