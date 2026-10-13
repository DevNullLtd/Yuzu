# SCIM v2 Provisioning

SCIM 2.0 (System for Cross-domain Identity Management, RFC 7643/7644) lets
an enterprise identity provider — Okta, Microsoft Entra ID, OneLogin, and
others — automatically create and disable Yuzu operator accounts as people
join, move, and leave your organization, instead of an admin managing
accounts by hand in the dashboard. This is the standard mechanism auditors
look for when assessing SOC 2 **CC6.2** (provisioning) and **CC6.8**
(termination).

> **Groups→role mapping is supported.** Push SCIM `Group` resources and
> configure `--scim-admin-group` to grant `role=admin` to members of a
> configured admin group, the same pattern [SAML](authentication.md#saml-group-to-role-mapping)
> and OIDC already support. Without that flag set, every SCIM-provisioned
> account stays the fixed, read-only `user` role — see
> [What gets provisioned](#what-gets-provisioned) and
> [Groups → role mapping](#groups--role-mapping) below.

## What SCIM does

Once enabled, your IdP's SCIM connector talks to `https://<your-server>/scim/v2`
using a bearer token you configure. From then on:

- **New hire assigned the Yuzu app in the IdP** → the IdP calls
  `POST /scim/v2/Users` → a Yuzu account is created automatically, ready to
  sign in via SSO.
- **Employee terminated / unassigned from the app in the IdP** → the IdP
  calls `PATCH`, `PUT` (or `DELETE`) → the Yuzu account is disabled
  immediately, and any active session for that user is revoked. No admin
  has to remember to go disable the account by hand.
- **Employee later re-assigned / re-hired** → the IdP re-activates the same
  SCIM resource → the Yuzu account is restored (any stale account lockout
  is cleared). The user re-enrolls MFA on their next login — a reactivation
  never resurrects an old second factor. A returning employee whose account
  was fully deprovisioned and later re-`POST`ed by the IdP is also handled —
  see [Reprovisioning a returning employee](#reprovisioning-a-returning-employee)
  below.

## Enabling SCIM

Two flags, both required together:

| Flag | Env var | Description |
|---|---|---|
| `--scim-enable` | `YUZU_SCIM_ENABLE` | Turns on the `/scim/v2/*` endpoint surface. Default `false` — the surface does not exist at all until you opt in. |
| `--scim-token` | `YUZU_SCIM_TOKEN` | The bearer credential your IdP's SCIM connector will authenticate with. Generate a long random secret and treat it like a password (a 32+ byte random hex/base64 string is a good choice). |

**Prefer the environment variable.** A `--scim-token` value passed on the
command line is visible to any local user via `ps`/`/proc/<pid>/cmdline`;
`YUZU_SCIM_TOKEN` is not. Use the env var as the primary method:

```bash
export YUZU_SCIM_TOKEN="$(openssl rand -hex 32)"
./yuzu-server \
  --https-cert    /etc/yuzu/server.crt \
  --https-key     /etc/yuzu/server.key \
  --scim-enable
```

(`--scim-token` remains available for local/manual testing, but is not
recommended for a production invocation for the `ps`-visibility reason
above.)

**The server refuses to start** in either of these cases:

- `--scim-enable` is set but `--scim-token` is not — there is no safe way
  to expose the provisioning surface without a credential gating it.
- `--scim-enable` is set together with `--no-https` — the bearer token is a
  credential capable of creating and disabling operator accounts; it must
  never be sent in plaintext. **SCIM requires HTTPS.**

The server logs its SCIM posture once at startup so you have a record of
when provisioning was turned on (compliance evidence for CC6.2).

## Configuring your IdP's SCIM connector

Point your IdP's SCIM connector at the base URL and supply the bearer token:

- **SCIM base URL:** `https://yuzu.example.com/scim/v2`
- **Authentication:** Bearer token — enter the same value you set with
  `YUZU_SCIM_TOKEN` (or `--scim-token`).

> **Required: map `userName` to a slug, not an email address.** Yuzu account
> usernames only allow letters, numbers, `.`, `_`, and `-` — no `@`. Most
> IdPs (Okta, Entra ID) default a new SCIM app's `userName` mapping to the
> user's email address, which will cause every provisioning call to fail
> `400`. Before assigning any users, open the connector's attribute-mapping
> screen (Okta: "Provisioning" → "To App" → attribute mappings; Entra ID:
> "Provisioning" → mapping editor) and change the `userName` source
> attribute to something slug-shaped — e.g. the part of the email before
> the `@`, an employee ID, or another existing non-email directory
> attribute. Native support for an email-shaped `userName` is on the
> roadmap; until then this remapping step is required.

Consult your IdP's SCIM setup documentation for the exact steps (Okta:
"SCIM Provisioning" app integration wizard; Entra ID: "Provisioning" tab on
the Enterprise Application). Yuzu implements the standard discovery
endpoints (`ServiceProviderConfig`, `ResourceTypes`, `Schemas`) that most
connector wizards use to auto-detect capabilities — after entering the base
URL and token, use your IdP's "Test Connection" button to confirm the
handshake works before assigning any users.

Once connected, assign users/groups to the Yuzu application in your IdP as
you would for any other SCIM-provisioned app; the IdP handles the
create/update/deactivate calls automatically from that point on.

## What gets provisioned

A user created via SCIM:

- Is assigned the **`user` role** (read-only, floor privilege) by default —
  unless they are already a member of your configured
  [`--scim-admin-group`](#groups--role-mapping) at the moment of
  provisioning, in which case they are created `role=admin` directly. No
  other group or role attribute the IdP might send has any effect on role.
- Gets a **random, discarded password** — SCIM users never log in with a
  local password. They authenticate through your SSO flow (OIDC or SAML)
  the same as any other SSO user.
- Is tracked with a **provisioning source of "scim"**. This matters for
  deprovisioning safety (see below): a locally-created admin account, or
  the emergency break-glass account, can never be touched by a SCIM
  deactivate/delete call — even if the IdP or connector is compromised or
  misconfigured. A SCIM push can only ever affect accounts it created.

If you need admin access for a SCIM-provisioned person, configure
[Groups → role mapping](#groups--role-mapping) below — or, if you'd rather
keep it independent of SCIM entirely, grant it through
[OIDC group→role mapping](authentication.md#group-to-role-mapping) or
[SAML group→role mapping](authentication.md#saml-group-to-role-mapping)
instead; all three mechanisms are independent and unaffected by one another.

## Groups → role mapping

Your IdP can push SCIM `Group` resources, and Yuzu can grant `role=admin` to
any SCIM-provisioned user who is currently a member of one configured admin
group — mirroring how [SAML group→role mapping](authentication.md#saml-group-to-role-mapping)
and OIDC group→role mapping already work.

### Endpoints

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/scim/v2/Groups` | Create a group (`displayName`, optional `members[]`) |
| `GET` | `/scim/v2/Groups/{id}` | Read a single group |
| `GET` | `/scim/v2/Groups` | List groups (`startIndex`/`count` pagination, optional `filter=displayName eq "..."`) |
| `PUT` | `/scim/v2/Groups/{id}` | Replace a group |
| `PATCH` | `/scim/v2/Groups/{id}` | Add/remove members (RFC 7644 §3.5.2 PatchOp on the `members` path) |
| `DELETE` | `/scim/v2/Groups/{id}` | Delete a group |

`Group` is now advertised in `/scim/v2/ResourceTypes` and `/scim/v2/Schemas`
(schema urn `urn:ietf:params:scim:schemas:core:2.0:Group`) alongside `User`.

**Group size is bounded.** Each Group create/replace/patch enforces a
bounded maximum on `members[]` — a request that would push a group past
that bound is rejected rather than silently truncated or accepted
unbounded. If your admin group is very large, split membership pushes
across multiple `PATCH` calls.

### Configuration

| Flag | Env var | Description |
|---|---|---|
| `--scim-admin-group` | `YUZU_SCIM_ADMIN_GROUP` | The `displayName` of the SCIM group whose members are granted `role=admin`. Default empty — no SCIM group grants admin, and every SCIM-provisioned user stays `role=user`. The value is whitespace-trimmed at load. |

`--scim-admin-group` mirrors `--saml-admin-group`: set it to the exact
`displayName` of the group in your IdP that should map to Yuzu admin
(case-sensitive, exact byte match — no wildcard/prefix matching, and no
leading/trailing whitespace tolerance beyond the trim above).

**Requires a restart to take effect.** `--scim-admin-group` is read once at
startup; changing it (or renaming the mapped group's `displayName` in the
IdP) requires updating the flag and restarting the server — there is no
live-reload or Settings-UI path. A restart alone does not re-evaluate any
user's membership; see [Recovery and alerting](#recovery-and-alerting)
below for how to force re-evaluation after a config fix.

### How role is resolved

Because Yuzu's role model is binary (`admin` or `user`), the mapping is a
simple parity check: a SCIM-provisioned user is `role=admin` **if and only
if** they are currently a member of the group named by `--scim-admin-group`;
otherwise they are `role=user`. Role is recomputed whenever it could have
changed — on user creation, and on any Group create, replace, patch, or
delete that could add or remove the user from the admin group. Removing a
user from the admin group demotes them back to `user` on the next
recomputation; it does not require a separate role-change call.

### Provenance guard still applies

Role changes driven by Group membership only ever touch accounts with
`provisioning_source == "scim"` — the same guard that protects deactivate/
reactivate/delete (see [What gets provisioned](#what-gets-provisioned)
above). If a Group's `members[]` list includes the SCIM `id` of a
non-SCIM account (a locally-created admin, or the `--break-glass-user`
account), that member is **never** role-changed. A compromised or
misconfigured IdP cannot use Group push to elevate, demote, or otherwise
touch a local principal.

### Manual role changes to a SCIM account are not durable

For a SCIM-provisioned account, IdP group membership — not a manual
dashboard edit — is the authoritative, durable source of truth for role.
If you (or another admin) manually change a SCIM-provisioned user's role
from the dashboard, that change is **reverted back to the group-derived
role the next time something recomputes that user's membership** — a
Group `POST`/`PUT`/`PATCH`/`DELETE` that touches this user, or the user
being reprovisioned (a `POST` reviving a deactivated account). It is
**not** reverted by a plain deactivate/delete attempt (the deprovision
guard blocks those against a non-`user` account before any recompute runs
— see [Deprovisioning order matters for group-granted admins](#deprovisioning-order-matters-for-group-granted-admins)
below), and it is **not** reverted by a server restart or by changing
`--scim-admin-group` itself — both require a subsequent Group mutation to
actually re-evaluate membership.

**One residual case:** if you manually promote a SCIM-provisioned user to
`admin` and that user is not a member of *any* SCIM group, there is no
membership-recompute event that will ever touch them, so the manual
promotion is neither reverted nor is the account SCIM-deprovisionable
(the deprovision guard still blocks it) — an operator must demote it by
hand. This is a pre-existing residual carried over from the Users slice,
not new in Groups → role mapping.

### Deprovisioning order matters for group-granted admins

The SCIM deprovision role-guard refuses to delete or deactivate an account
whose role is not `user` (it returns `404`, not a `403` that would confirm
the account exists). This means **a user who is `admin` via group
membership cannot be SCIM-deprovisioned until the IdP first removes them
from the admin group** — which demotes them back to `user`, at which point
the next deactivate/delete call succeeds normally. The one exception: if that
user is the last protected administrator, the demotion is refused instead, the
role stays `admin` and the `404` persists until another active local administrator
account (`role` `admin`) exists AND the user's role is demoted by hand, signed in as
that other administrator (`POST /api/settings/users/{username}/role` with `{"role":"user"}`;
the dashboard has no role button, and "If the guard refuses an action you intend"
in [`rbac.md`](rbac.md) lists the steps, including step-up and the break-glass exit), or by a later change
that names the user, for example through another group they belong to; a
re-send of the same Group change cannot do it, because the member has already
left the group (see "The fleet's last administrator is protected" and "Group role recompute:
when it is incomplete" under
[Deprovisioning and termination](#deprovisioning-and-termination)).

In practice this is not extra work: standard Okta/Entra offboarding already
removes a departing employee from all their groups (including any admin
group) as part of unassigning the app, before or as part of deactivating
the user. As long as your offboarding flow follows that normal order —
remove from groups, then deactivate/delete — deprovisioning a group-granted
admin behaves exactly like deprovisioning any other SCIM user.

### Recovery and alerting

Deploy these alert rules alongside SCIM Groups → role mapping:

- **`yuzu_scim_role_change_failures_total > 0`** — a role change was decided
  but did not complete: the guarded write failed (the role may not have
  changed), or the role did change but its durable session wipe failed.
  Investigate immediately; the account may be running with a role or a
  session that does not match its IdP group membership until fixed.
- **A spike in `rate(yuzu_scim_role_changes_total[5m])`** — a sudden burst
  of role changes is the signature of an IdP-side misconfiguration or
  accidental mass group edit (e.g. someone attached the wrong group to the
  Yuzu app, or bulk-edited the admin group's membership), not routine
  churn. Alert on a rate threshold well above your organization's normal
  onboarding/offboarding cadence.
- **`yuzu_scim_group_recompute_skipped_total{cause}` > 0**: a Group request
  did not apply (or could not determine) every member's role: `promotion`
  (skipped after a failed guarded write) or `undetermined` (a read failed).
  Find the members in the `scim.group.recompute_incomplete` audit row for the
  Group (first 20 named; the count is exact) and repair them by hand; see
  "Known limits of the Group role recompute" below and the Troubleshooting
  entry "A Group change was reported incomplete". A failed demotion is counted
  on `yuzu_scim_role_change_failures_total`, and a refused one on
  `yuzu_server_rbac_last_admin_guard_refused_total{transport="scim"}` (the
  last-Administrator refusal counter). No alert rule ships for this counter
  or for `yuzu_scim_compensation_failed_total` yet; both are tracked in
  #5673.
- **`yuzu_scim_audit_write_failures_total`** — the existing CC6.8
  evidence-integrity alert; it also covers a lost audit row for a group
  create/update/delete or role-change event (the SCIM call and the role
  change themselves still succeeded — only the evidence row is missing).

**Remediation for a misconfigured `--scim-admin-group`:** fix the flag
value and restart the server (see [Configuration](#configuration) above —
this flag is not live-reloadable). **A restart alone does not fix already
wrong roles** — it only changes which group name new recomputes will
check against; any user whose role drifted under the old value stays
drifted until a recompute actually runs for them. To force re-evaluation
of every member's role after correcting the flag, re-`PATCH` the affected
group(s) (even a no-op add/remove of an already-current member triggers
`recompute_scim_user_role` for every affected user) rather than waiting for
the IdP's next natural sync.

### Example: Okta/Entra Group push

Creating the admin group and adding a member:

```http
POST /scim/v2/Groups
Authorization: Bearer <scim-token>
Content-Type: application/scim+json

{
  "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
  "displayName": "yuzu-admins",
  "members": [
    { "value": "<scim-user-id>" }
  ]
}
```

Adding a member to an existing group via `PATCH` (the form most IdP
connectors issue when a user is later assigned to the group):

```http
PATCH /scim/v2/Groups/{id}
Authorization: Bearer <scim-token>
Content-Type: application/scim+json

{
  "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
  "Operations": [
    {
      "op": "add",
      "path": "members",
      "value": [{ "value": "<scim-user-id>" }]
    }
  ]
}
```

Removing a member (e.g. as part of offboarding, before deactivating the
user) uses the same `PATCH` shape with `"op": "remove"`. Set
`--scim-admin-group` to `yuzu-admins` (or whatever `displayName` you chose)
for this group's membership to grant `role=admin`.

## Deprovisioning and termination

When your IdP deactivates or removes a user's app assignment, it sends a
`PATCH` or `PUT` (setting `active: false`) or a `DELETE`. Any of the three
has the same effect:

- The Yuzu account is disabled immediately.
- Any session the user currently holds is revoked — they are logged out,
  not just blocked from a future login.
- The action is recorded in the audit log (`scim.user.deactivated` /
  `scim.user.deleted`), giving you a timestamped record for termination
  evidence (CC6.8).

> **API/MCP tokens ARE now revoked on deprovision — including federated
> (SSO) tokens, if the user is linked.** SCIM deprovisioning (and the
> dashboard's manual delete) revokes the user's **sessions and their API/MCP
> tokens**, both for the SCIM slug itself and for any OIDC identity linked
> to it (see [SCIM ↔ OIDC identity linkage](#scim--oidc-identity-linkage-federated-token-revocation)
> below for how the link forms and what to configure), as well as any
> **SAML** session linked to it (SAML has no separate token-mint path; any
> token minted under a SAML principal is revoked with that principal — see
> [SCIM ↔ SAML identity linkage](#scim--saml-identity-linkage-federated-session-revocation)
> below). Revocation is durable
> within roughly **60 seconds** of the deprovision reaching Yuzu — a
> concurrently in-flight request can still see a token as valid for that
> brief window (the `ApiTokenStore` in-memory validate cache), but the
> revoke itself has already committed. This closes the former gap tracked as
> [#2022](https://github.com/Tr3kkR/Yuzu/issues/2022). **Two things this does
> NOT cover:** (1) a SCIM slug that was elevated to admin *outside* SCIM —
> its linked federated identity's tokens are deliberately NOT
> auto-revoked; a human must terminate them manually (see D1 below); (2) an
> IdP whose SCIM `externalId` shares no value with any OIDC claim Yuzu
> validates — there is no join key to link on, so nothing federated can be
> revoked by SCIM for that population (see D2 below).

Deprovision is **credentials-first**: tokens and sessions are revoked for
the slug and every linked identity *before* the account is marked inactive
or deleted, and if any token revoke does not durably persist, the whole
deprovision call fails with a **`500`** rather than reporting success — this
is new behavior your IdP connector's retry/alerting should account for: a
`500` on a deactivate/delete call means the underlying store had a transient
problem persisting the revoke, and the IdP should retry the call rather
than treat it as a permanent rejection.

**SCIM will not deactivate an account that is currently `role=admin`,**
whether that admin role came from a dashboard promotion or from
[Groups → role mapping](#groups--role-mapping) — that account drops out of
SCIM's reach until it is back to `role=user`, and an IdP-side deactivate/
delete call against it is refused in the meantime. This is a
**demote-before-delete ordering gate**, not a guarantee that a manual
promotion is permanently protected: SCIM simply must never be able to
deprovision a non-`user` account without an explicit, auditable demotion
happening first. For a group-granted admin, see
[Deprovisioning order matters for group-granted admins](#deprovisioning-order-matters-for-group-granted-admins)
above for the expected offboarding order; for a manually-promoted account,
see [Manual role changes to a SCIM account are not durable](#manual-role-changes-to-a-scim-account-are-not-durable)
above — a manual promotion is not otherwise durable, but demotion is still
a required, explicit step before SCIM can deprovision the account.

**The fleet's last administrator is protected: a `409`.** When RBAC enforcement
is on, a deprovision (or a `POST` with `active:false`) of the account that
holds the fleet's only `Administrator` grant is refused with **`409`** and
`scimType: "mutability"`, audited as `scim.user.last_administrator_refused` and
counted on `yuzu_server_rbac_last_admin_guard_refused_total{transport="scim"}`.
(`role=admin` accounts never get this far; they are the `404` above.) Yuzu
checks first, before revoking anything, and answers `409` with nothing changed.
If that early check passed and the guard refuses afterwards, the response says
the account's linked credentials (API tokens and sessions, including linked
OIDC/SAML identities) were **revoked before the refusal** and that the account
**remains active**, because revocation comes first (see above). Two things for
your connector: a `409` does not prove an IdP will stop retrying, so expect the
same request again on the next sync (every attempt is audited and counted and
raises a critical analytics event; the server log line is limited to one
warning per username per minute); and resolving it is an operator action, not
an IdP one: grant the `Administrator` role to another active local account first (a principal with no active `auth.users` row, or an inactive one, is not counted). Do this before the identity provider removes the member: once the refusal has fired, only direct SQL can add it for anyone but the member (see [`rbac.md`](rbac.md), "If the guard refuses an action you intend"). Until then
the person the IdP terminated is still active here: after an early refusal
their API tokens and sessions are live as well, and after a late one the
account remains active in Yuzu, so any credential the IdP still accepts for it
works; revoke them by hand if that matters. If the
guarded write times out or the store is unavailable the answer is **`503`** with
`Retry-After: 2` (header only; the body is the plain SCIM error, with no
`retry_after_ms` member) and a detail saying the account state may be
indeterminate. The linked credentials were already revoked. A retry finishes the
job only when the cause was a lock timeout and nothing committed (`PATCH`, `PUT`,
`DELETE`); it does not converge after a lost commit acknowledgement (the retry
meets the `404` role guard on the now-deactivated account), and not for a `POST`
with `active:false` (the account stays active and mapped, and the retry gets the
`userName` `409`). A `500` after a failed session wipe means the account IS
deactivated, and a retry of that request is not promised to repeat the wipe
([#5214](https://github.com/Tr3kkR/Yuzu/issues/5214)). When a Group change would demote the last active
local admin account, the Group request still succeeds, the account keeps its
role, the refusal is audited the same way and raises a critical analytics
event (the IdP removed the person from the admin group and they keep admin: an
operator has to act). The audit action `scim.user.last_administrator_refused`
and the counter are the signals that always fire; the critical analytics event
is a no-op under `--no-analytics`. A late refusal is audited with `result=partial` (the
credentials were revoked); an early refusal and a refused demotion are
`denied`.

**Group role recompute: when it is incomplete.** After a Group create, replace,
patch or delete commits, Yuzu recomputes the role of each affected member, the
members the request REMOVES first. Every **demotion** is attempted (skipping one
would leave an IdP-removed administrator holding the role). After the first
failed guarded write (a lock wait that expired, an unavailable store) the
remaining **promotions** are skipped. A member whose read failed (its SCIM
resource, provisioning source, group memberships or current role) is
**undetermined**: its role is left untouched and it is recorded. Nothing is
dropped silently:

- a refused demotion (the last-Administrator guard) writes the
  `scim.user.last_administrator_refused` row and counter and a critical analytics
  event;
- a failed demotion writes a `scim.user.role_changed` failure row (with
  `role_applied=unknown` when the write may have committed and its outcome is
  not known), increments `yuzu_scim_role_change_failures_total`, raises the
  critical analytics event `scim.user.role_demotion_incomplete` and a critical
  log line saying the IdP-removed administrator retains or may retain the role:
  verify the account's role (demote it if it is still `admin`) and revoke its
  sessions by hand. A failed promotion also counts in `failed=` (it has no
  critical event);
- when anything was refused, failed, undetermined or skipped, ONE
  `scim.group.recompute_incomplete` audit row (`result=partial`) records the
  count per class and up to 20 usernames (or `scim_id:<id>`) per class (first 20
  named; the count is exact), and
  `yuzu_scim_group_recompute_skipped_total{cause="promotion"|"undetermined"}`
  counts the skipped promotions and the undetermined members;
- the Group `created`/`updated`/`deleted` success row says `recompute=complete`
  only when every member was recomputed as intended, otherwise
  `recompute=incomplete`. The Group request keeps its status (its membership
  write committed) and the member may keep the role.

To replace the ONLY administrator through the admin group, add the new
administrator in one Group change and remove the old one in a second. A single
change that does both demotes the old administrator first (removed members are
recomputed first): the guard refuses, because the new administrator is not yet an
administrator and no other exists. The old administrator keeps the role, the new
one is promoted afterwards, the request says `recompute=incomplete`, and the old
administrator has to be demoted by hand (see the remedy below).

**Known limits of the Group role recompute.** These are real gaps, tracked in
#5673. Until then they are documented rather than engineered
around:

1. Group mutations are serialized within one server process. When more than one
   server replica runs, send SCIM provisioning traffic to a single replica.
   `POST /Groups` does not take the per-process Group lock (`PUT`, `PATCH` and
   `DELETE` do).
2. There is no reconcile, and a re-send does not reach a member who has already
   left the group. A failed or refused write IS reported: the group's success
   row says `recompute=incomplete` and a `scim.group.recompute_incomplete`
   summary row names the members. But re-sending the same `PUT` or `PATCH`
   recomputes only the old and the current members of the group at that moment,
   so it re-derives skipped promotions and undetermined members still in the
   group and can never re-derive a member who has left it. A retried `DELETE`
   never reaches the recompute (the group is gone: `404`, or an idempotent
   `204`), and an IdP's next sync sends no change for a member who is already
   out. For a **refused**, **failed** or **undetermined** demotion of a member
   who has left the group, demote the member by hand with
   `POST /api/settings/users/{username}/role` with `{"role":"user"}` (the dashboard has no role button. Make the call while signed in as an administrator other than that account, because a self-target answers `403` `self_role_change_blocked`. It needs a cookie session (an account with MFA enrolled also needs a fresh step-up: a proof older than `--mfa-step-up-window-secs`, default 300 s, answers `401` with `meta.mfa_step_up_required`, and a fresh password plus TOTP login counts; an account with no MFA enrolled is not challenged under the default `--mfa-enforcement=optional`; a SAML session gets `403`) or an administrator API token (`Authorization: Bearer` or `X-Yuzu-Token`), which is never challenged for step-up; see [Changing a User's Role](server-admin.md#changing-a-users-role)). For a refused one, a second active local
   administrator account has to exist first and the call has to be made as that
   second administrator; see [`rbac.md`](rbac.md), "If the guard refuses an
   action you intend", for the steps and for the break-glass exit when no
   administrator session can pass step-up (promote and arm the break-glass
   account first, and revert it afterwards). A later
   change that names the user through another group they belong to also
   re-derives their role. A skipped **promotion** is the exception: a re-send
   of a `PUT` or `PATCH` retries it while the member is in the group, but a
   `DELETE` never can.

   *Crash breadcrumb.* Once a `PUT`, `PATCH` or `DELETE` has committed the
   membership change and either removed at least one member or renamed the
   group so that the admin-group match flips (the rename changes the role of
   every current member), the server writes ONE log line at WARN level before
   the first role change and flushes the log right after it: `SCIM: Group
   scim_id=<id> membership change committed; role recompute starting for <N>
   removed member(s): <ids>[,+M more]`. When the rename flips the match the line
   ends `; the group rename changes the admin-group match and <K> current
   member(s) will be recomputed` (and the removed-members part is absent if
   nobody was removed). WARN is written at the default log level and at
   `--log-level warn`; it is not written at `error` or `off`. It names the first
   20 removed members by SCIM ID (not by username: the line performs no store
   read, so it cannot be delayed by a degraded store; resolve an ID with
   `GET /scim/v2/Users/<id>`) and `<N>` is the exact count. It is not written by
   `POST`, or by a change that removed nobody and did not flip the match of a
   group that still has members (an add-only change writes none, and neither
   does a flipping rename of an empty group; a re-send recovers it). It is also written on
   the idempotent already-gone path of a `DELETE`, which is reachable only
   through a cross-process race. Without `--log-file` the line goes to stdout
   (with `--log-file`, to stderr and the file); journald and container logs
   capture both, and only the null-logger fallback writes to stderr directly. The flush precedes the recompute, so the line survives a `SIGKILL`
   once written to the sink in use (a file sink may still hold a copy that was
   not yet written; the copy the console stream already took is not lost), but not power
   loss or a kernel panic (there is no fsync). If writing it fails, the failure
   never blocks the recompute. Where a crash stopped the request, read the
   signature:

   | Crash point | What remains |
   |---|---|
   | Before the membership commit | Nothing changed. |
   | After the commit, before the breadcrumb line | No record of the removed members. |
   | Mid-recompute | The breadcrumb, only when members were removed or the rename flips the match (an add-only change writes none; a re-send recovers), and the per-member rows written so far; no summary row and no `recompute=` marker, and no Group success row. |
   | After the recompute, before the Group success row | The breadcrumb (when one applies), the per-member rows and any summary row; roles are as the recompute left them (read the summary row); the Group success row is missing. |

   The first two rows are indistinguishable by signature (a crash before the
   commit, and a commit whose acknowledgement was lost, both leave nothing). The
   last row's signature is also what a failed final read of the group looks like
   when it follows the recompute: a `PUT` then writes a failure row with an
   empty detail and answers `500`, and a `PATCH` writes no row.

   Per-member rows written before a crash persist. After any unclean restart,
   compare the IdP's admin-group membership with the Yuzu roles and demote the
   difference.
3. A Group request recomputes every affected member and can be slow on a large
   group or a slow store; the HTTP request and the per-process Group lock
   (taken by `PUT`, `PATCH` and `DELETE`, not by `POST`) are held meanwhile.
   There is no time bound on the loop.
4. A Group `POST` that fails after the group row is created leaves an empty
   group, and a retry answers `409`.
5. Deactivation of an account whose role is not `user` is refused with `404`
   until the role is corrected.
6. `POST /Users` re-provisioning recomputes the one user but ignores an
   incomplete result. An undetermined result on that revive path leaves only a
   log line: no audit row and no counter. The other revive paths (`PATCH` and
   `PUT` with `active:true`) do not recompute the group role at all, so an
   inactive member added to the admin group stays `user` until the next Group
   change (this predates the last-Administrator guard).
7. A deactivation whose SCIM mirror write failed is not retried to convergence.
   The auth account is already deactivated, the request answers `500`, the SCIM
   resource still reads `active=true`, and the IdP's retry answers `404` (the
   role guard finds no active account), so the mirror stays stale until it is
   reconciled ([#5214](https://github.com/Tr3kkR/Yuzu/issues/5214), and the
   follow-up tracked in #5673). Every IdP retry also hits the
   role guard: it answers `404`, writes a `scim.user.provenance_denied` audit
   row and increments `yuzu_scim_provenance_denied_total`, which drives the
   shipped `YuzuScimProvenanceDenied` alert (`increase(...[1h]) > 0`, severity
   warning): it fires, and stays firing while the retries continue. There is no hand
   remedy today (no route and no SQL statement is documented for it) until #5214
   and #5673 land.

**Pilot playbook.** No alert rule ships for the SCIM Group role recompute or for the
last-Administrator refusals yet (tracked in #5673). Until it does, key your SIEM or log
pipeline on these three audit actions, each of which means an operator has to look at an
account: `scim.user.last_administrator_refused` (a person the IdP removed keeps
administrator access, or a deprovision was refused), `scim.user.compensation_failed` (a
half-finished create was not undone) and `scim.group.recompute_incomplete` (a Group
change did not reach every member as intended). They are written whether or not
`--no-analytics` is set.

See
[`rbac.md`](rbac.md#last-administrator-guard-for-account-deactivation-and-demotion).

`POST /scim/v2/Users` also refuses (`404`, nothing created or reactivated) a
`userName` that already holds an `Administrator` grant, or whose deactivated
record still has a role other than `user`: a SCIM account must never become a
counted administrator. A `PATCH`/`PUT` with `active:true` applies the same two
checks before reactivating (behavior change: such a request used to reactivate
the account). Every such `404` increments `yuzu_scim_provenance_denied_total`,
the compromised-IdP signal, so this benign case also fires it. An elevated
tombstone cannot be re-enabled through SCIM or the dashboard until its role is
cleared (see [`rbac.md`](rbac.md#last-administrator-guard-for-account-deactivation-and-demotion)). The `404` tells the holder of the SCIM bearer, with
no side effect, that the name holds a grant or an elevated deactivated record.
These checks read the RBAC store, so SCIM provisioning needs it even when RBAC
enforcement is off; if the grant read is unavailable the answer is `503` with
`Retry-After: 2` and nothing is created.

If the person is later re-added in the IdP, the same SCIM resource is
reactivated (`active: true`): the account comes back, any lockout state is
cleared, but **MFA is not restored** — they will re-enroll TOTP the next
time they sign in.

## SCIM ↔ OIDC identity linkage (federated token revocation)

If your users sign in via SSO (OIDC — Okta, Entra, etc.) rather than a
Yuzu-local password, their API/MCP tokens are minted under a **separate**
`oidc:<issuer>#<subject>` identity, not their SCIM slug. Without a link
between the two, SCIM deprovisioning the slug would leave those federated
tokens untouched. Yuzu forms this link automatically at login and revokes
across it on deprovision — this section covers the one flag you may need
to set, plus the two detection signals that tell you if it isn't working
for a given IdP.

### Choosing the link claim for your IdP

| Flag | Env var | Description |
|---|---|---|
| `--oidc-scim-link-claim` | `YUZU_OIDC_SCIM_LINK_CLAIM` | Which validated OIDC ID-token claim is compared against a SCIM resource's `externalId` to form the link. Default `sub`. Only `sub` and `oid` are accepted — boot fails closed on any other value. |

**Set this per IdP, not by guessing:**

| Your IdP | What SCIM's `externalId` actually is | Set `--oidc-scim-link-claim` to |
|---|---|---|
| Okta | The user's OIDC `sub` | `sub` — the default; no change needed |
| Microsoft Entra ID | The Azure AD object id, which shows up in the ID token as the `oid` claim (Entra's `sub` is a *different*, app-specific value) | `oid` |

If you are not sure which your IdP uses, check the D2 signal
(`yuzu_scim_deprovision_unlinked_total`, below) after a real federated user
has both logged in once and later been deprovisioned — a non-zero bump
means the claim you configured did not match, and it's worth trying the
other allowed value.

**Some IdPs cannot be linked at all, by design, no matter what you set
here.** If your IdP's SCIM `externalId` is neither the OIDC `sub` nor the
`oid` claim — no shared, IdP-asserted value exists between the SCIM push and
the OIDC login — there is no join key available and federated tokens for
that population cannot be revoked by SCIM. This is a design limitation
(only IdP-asserted, stable claims are trusted for a security-relevant join;
mutable fields like email are never used), not a bug to work around. Treat
manual token revocation as a required, explicit offboarding step for that
IdP until it exposes a shared claim.

### Availability: a ScimStore/Postgres outage denies ALL OIDC logins

Deny-at-login (the check that refuses re-login for an already-deprovisioned
identity) is fail-**closed**: if `ScimStore` cannot answer — a Postgres
outage or degradation — the check treats that the same as "deprovisioned"
and denies the login. This is the correct tradeoff (a login Yuzu cannot
verify as safe is treated as unsafe), but it is a new availability coupling
worth knowing about before you flip `--scim-enable` on: **once SCIM linkage
is enabled, a `ScimStore`/Postgres degradation denies every OIDC login
fleet-wide** — not just deprovisioned users, but anyone signing in via SSO,
including a user who was never SCIM-linked at all. **Password login is not
affected** — this coupling is OIDC-only.

`yuzu_auth_oidc_deprovisioned_denied_total` is the **sum** of two sub-counters
(#3069): `yuzu_auth_oidc_deprovisioned_denied_genuine_total` (a real
deprovisioned identity was refused re-login — the CC6.8-alertable signal) and
`yuzu_auth_oidc_deprovisioned_denied_store_unavailable_total` (a fail-closed
deny while `ScimStore`/Postgres could not answer the check — an *availability*
event, not a termination). **Alert on the `_genuine_total` sub-counter, not the
total** — the shipped sample rule `YuzuAuthOidcDeprovisionedDeniedGenuine`
(`docs/prometheus/yuzu-alerts.yml`) does exactly this, so a Postgres outage can
never trip it. The SAML side has the identical split
(`yuzu_auth_saml_deprovisioned_denied_{genuine,store_unavailable}_total`). If
you are only watching the total, still correlate a spike with Postgres health —
`yuzu_pg_acquire_wait_seconds` / `yuzu_pg_acquire_timeout_total` — before
assuming a wave of terminated users is trying to log back in.

### The ~60 second window

A deprovision revokes tokens and sessions **immediately** at the store
level, but an already-validated API/MCP token can keep passing validation
for **up to ~60 seconds** afterward due to an in-memory cache — a
concurrently in-flight request may briefly still see the old "valid"
answer. Cookie sessions have no such cache and are revoked instantly. The
honest guarantee is "revoked within about a minute of the deprovision
reaching Yuzu," not instantaneous — plan any time-sensitive incident
response (e.g. a hostile termination) with that window in mind, and
consider pairing it with a device-level action (Guardian/EDR) for anything
requiring sub-minute containment.

### D1 — a deprovision refused because the account was elevated outside SCIM

`deprovision_role_ok` (see [Deprovisioning order matters for group-granted
admins](#deprovisioning-order-matters-for-group-granted-admins) above)
already refuses to deprovision an account that isn't `role=user` — this is
deliberate, so a compromised or misbehaving IdP can't unilaterally tear down
an admin. When that refusal happens for a slug that also has an active
linked federated identity, Yuzu does **not** silently leave the situation
alone: it always writes an audit row (`scim.user
.deprovision_role_refused_with_link`, `result=failure`) and always bumps
`yuzu_scim_deprovision_role_refused_with_active_link_total`. **Alert on the
metric or the audit action — that is the reliable, always-on signal.** (If
you also have analytics event collection enabled — the default, unless you
pass `--no-analytics` — the same event additionally lands there at critical
severity; that is a bonus channel for a deployment that already consumes
analytics events, not the primary detection mechanism, and it is not
present if analytics collection is disabled.)

**What to do:** the underlying account was terminated by the IdP but is
still elevated in Yuzu (either promoted by an admin, or via Groups → role
mapping), so SCIM refuses to touch it and its linked federated identity's
tokens are still live. Terminate that identity's tokens manually — from the
dashboard (Settings → API Tokens) or the REST API — and either demote the
account (letting the next IdP sync deprovision it normally) or otherwise
close it out by hand.

### D2 — a federated user logged in but their tokens weren't revoked

`yuzu_scim_deprovision_unlinked_total` fires when a deprovision finds
evidence that the user actually authenticated via OIDC, but no link had
formed to catch their tokens in the revoke. Every OIDC login records
**both** the `sub` and `oid` claim values it observed (not only the one
`--oidc-scim-link-claim` is currently configured to use), so this detector
also catches the specific, common misconfiguration where the *wrong* claim
is set — e.g. an Entra deployment left on the default `sub`, whose
`externalId` actually matches the login's `oid` value: the login observation
for `oid` still matches the slug's `externalId` at deprovision time even
though the link itself never formed on the `sub`-configured comparison.
**This is the tripwire for "my CC6.8 coverage for federated users is a
false green."** A non-zero rate means:

- Re-check `--oidc-scim-link-claim` against the [worked examples
  table](#choosing-the-link-claim-for-your-idp) above — the most common
  cause is Entra deployments left on the default `sub` instead of `oid`.
- If the claim is already correct for your IdP, your IdP's `externalId`
  simply doesn't correspond to either claim Yuzu records (`sub` or `oid`) —
  SCIM cannot revoke this population's federated tokens, treat manual
  revocation as a required offboarding step.

**What this does not do:** D2 is a detection signal, not a guarantee — it
only fires once a federated user has both logged in **and** later been
deprovisioned. A federated population that never triggers a deprovision
call in the window you're checking produces no signal either way; treat a
zero rate as "nothing detected yet," not as proof every federated user is
correctly linked.

## SCIM ↔ SAML identity linkage (federated session revocation)

If your users sign in via SAML SSO rather than a Yuzu-local password or
OIDC, a successful login can also form a durable link between their SAML
identity and their SCIM slug (ADR-2001 PR4a) — the SAML analogue of the
[SCIM ↔ OIDC identity linkage](#scim--oidc-identity-linkage-federated-token-revocation)
above. When the link exists, deprovisioning the SCIM slug revokes the
linked SAML session too, not just the slug's own credentials.

**What this does.** A SAML session's authorization principal is the stable
`saml:<entity_id>#<NameID>` string (`saml_principal_id`), not the raw
NameID — see [REST API Reference](rest-api.md) `DELETE /api/v1/sessions`.
At login, if the assertion's NameID resolves to exactly one active SCIM
resource by `externalId`, Yuzu upserts a `saml_identity_links` row for
`(entity_id, NameID)` → that resource. On a subsequent SCIM deprovision of
that resource, Yuzu looks up every linked SAML identity and revokes its
session, in addition to the slug's own.

**The NameID-Format contract.** Unlike OIDC (whose `sub`/`oid` claim is
always a stable, IdP-assigned value), a SAML NameID's stability depends on
its `Format`. Yuzu only forms a link when the asserted NameID's `Format` is
one of:

- `urn:oasis:names:tc:SAML:2.0:nameid-format:persistent`
- `urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress`

and its value equals the SCIM resource's `externalId`. A missing, empty, or
any other `Format` — including the SAML 2.0 `transient` format — is treated
conservatively as **not linkable**; no link forms and no error is raised
(the login still succeeds). That login is still recorded as a durable
observation for [D2](#d2--a-saml-user-logged-in-but-their-access-wasnt-revoked-on-deprovision)
below — including an empty/absent Format, which is observed as-is, not
dropped — the observation just never promotes into a link.

> **Warning — many IdPs default to `transient` NameID.** If your IdP issues
> a `transient` NameID (a common out-of-the-box default for a SAML 2.0
> application), **no link will ever form for that population, silently.**
> Deprovisioning those users' SCIM slugs will revoke the slug's own
> credentials but will **not** reach their SAML sessions — they can
> continue using an already-established SAML session until it naturally
> expires. Configure your IdP to assert a stable NameID Format
> (`persistent` or the SAML 1.1 `emailAddress` format) whose value equals
> the SCIM `externalId` you push for the same user, and verify the link is
> forming (watch `yuzu_scim_saml_link_write_failures_total`, below, and
> confirm no unexpected `0`-link population) before relying on this for
> offboarding evidence. If you can't fix the IdP's NameID Format
> immediately, `yuzu_scim_deprovision_saml_unlinked_total` (see
> [D2](#d2--a-saml-user-logged-in-but-their-access-wasnt-revoked-on-deprovision)
> below) is the deprovision-time backstop for exactly this
> unlinkable-NameID population — a bump there confirms an affected user
> was deprovisioned while still holding a live, unrevoked SAML session,
> even though no link ever formed to catch it directly.

**What deprovision-revoke actually does.** The linked-SAML-identity revoke
invalidates the user's active SAML session cookie(s), forcing
re-authentication. SAML has no separate token-mint path — any token minted
under a SAML principal is revoked with that principal on deprovision the
same way an OIDC-linked token is, so in practice a SAML deprovision's
observable effect is the session teardown described above.

**Metrics and audit verbs — SAML link health.** One existing write-failure
counter, plus four new #3072 counters and two new audit verbs (see
[D2](#d2--a-saml-user-logged-in-but-their-access-wasnt-revoked-on-deprovision)
below for how the latter six fit together):

- `yuzu_scim_saml_link_write_failures_total` (counter, no labels) — bumps
  when a SAML login's identity-link write **or** its D2 login-observation
  write fails (a ScimStore outage during the login window). The login
  itself always succeeds; both writes are fail-OPEN by design. A sustained
  non-zero rate means SAML identities are silently not linking, **and**
  D2's own detection is blind for those logins, during that window;
  correlate with ScimStore/Postgres health.
- `yuzu_scim_saml_link_unmatched_total`, `yuzu_scim_saml_link_ambiguous_total`,
  `yuzu_scim_saml_link_lookup_failures_total` — login-time D2 signals,
  backed by the `auth.saml.link_unmatched` / `auth.saml.link_lookup_failed`
  audit verbs.
- `yuzu_scim_deprovision_saml_unlinked_total` — the deprovision-time D2
  tripwire.

See [Metrics reference](metrics.md) for the full metric rows and [REST API
Reference](rest-api.md) for the audit-action table.

### Deny-at-login: a deprovisioned SAML identity cannot re-authenticate

In addition to revoking an already-live session on deprovision (above),
Yuzu also refuses a **new** SAML login for an identity whose linked SCIM
resource is already deprovisioned — the SAML analogue of [Availability: a
ScimStore/Postgres outage denies ALL OIDC
logins](#availability-a-scimstorepostgres-outage-denies-all-oidc-logins)'s
OIDC deny-at-login backstop above (ADR-2001 §4/PR3), shipped for SAML as
PR4b (#3066). Concretely: once a SCIM deprovision has landed for a linked
identity, that person presenting a still-valid, signed assertion from the
IdP is redirected to `/login?error=saml` instead of getting a fresh session
— the same generic error every other SAML login failure shows, so there is
no way for the browser to distinguish "you were deprovisioned" from any
other SAML failure.

This closes a gap that existed before PR4b shipped: a deprovisioned SAML
user could previously still obtain a brand-new session immediately after
their old one was revoked (correctly torn down again on the *next*
deprovision pass, but live in the meantime). **A re-login against an
already-completed deprovision is now refused,
unconditionally, no exceptions** — the same guarantee OIDC's PR3 gives you,
stated with the same honesty: a login racing an *in-flight* deprovision (the
deprovision and the login landing in the same narrow window) is narrowed by
a post-mint re-check that self-heals the overwhelming majority of timings,
but is not eliminated by construction — see [Availability: a
ScimStore/Postgres outage denies ALL OIDC logins](#availability-a-scimstorepostgres-outage-denies-all-oidc-logins)
above for the precise shape of that residual (same shape here, minus the
~60s API-token cache bound — SAML mints no tokens, so a session that does
slip through the in-flight race is bounded only by its own TTL, not ~60s).

**Availability coupling — same posture as OIDC, gated on `--scim-enable`.**
Deny-at-login for SAML fails **closed**: if `ScimStore` cannot answer, the
check treats that the same as "deprovisioned" and denies the SAML login too
— once `--scim-enable` is set, a `ScimStore`/Postgres outage now denies both
OIDC **and** SAML logins fleet-wide, not only OIDC's. With `--scim-enable`
off, the SAML ACS handler's SCIM store reference is null and this check is
inert — SAML login availability is unaffected, exactly as if the check were
absent.

**Audit and metric.** Every denial writes `auth.saml.deprovisioned_denied`
(`result=failure`) and increments `yuzu_auth_saml_deprovisioned_denied_total`
— see [REST API Reference](rest-api.md) and [Metrics
reference](metrics.md) for the full rows. As with the OIDC counter, a
sustained non-zero rate with no matching recent SCIM deprovision more likely
indicates a `ScimStore`/Postgres availability problem than a wave of
terminated users trying to log back in — correlate with Postgres health
before assuming every increment is a legitimate deny.

### D2 — a SAML user logged in but their access wasn't revoked on deprovision

Unlike OIDC's [D2](#d2--a-federated-user-logged-in-but-their-tokens-werent-revoked)
above — one detector, because OIDC has several candidate claims to
re-check after the fact — SAML's D2 (#3072) is a **pair** of complementary
signals, because SAML has only one candidate join key (the NameID). Every
SAML login is recorded as a durable observation, including one whose
NameID `Format` isn't linkable (see the NameID-Format contract above) —
this is what makes both signals below possible.

**Login-time signals (fire immediately; the login still succeeds).** For a
**stable**-Format NameID, the login-time link attempt already runs the
active-`externalId` lookup, so a failure to link is caught right away:

- `auth.saml.link_unmatched` (audit, `result=failure`) fires when the
  lookup found **no** active `externalId` match
  (`reason=no_active_external_id_match`) or **more than one**
  (`reason=ambiguous_active_external_id_match`) — check the audit
  `detail`'s `reason=` to tell them apart. Counted separately:
  `yuzu_scim_saml_link_unmatched_total` (no match) and
  `yuzu_scim_saml_link_ambiguous_total` (ambiguous — usually duplicate or
  stale `externalId` data in SCIM, a more actionable misconfiguration than
  ordinary IdP/SCIM drift).
- `auth.saml.link_lookup_failed` (audit, `result=failure`,
  `reason=scim_store_unavailable`) fires when the lookup itself couldn't
  be answered (a `ScimStore`/Postgres blip) — distinct from the above so a
  store outage is never misread as "this identity has no matching SCIM
  user." Counted by `yuzu_scim_saml_link_lookup_failures_total`.

**Deprovision-time tripwire.** `yuzu_scim_deprovision_saml_unlinked_total`
fires when a deprovisioned resource has **zero** linked SAML identities but
a recorded login observation shows a NameID matching its `externalId` —
this is the detector that catches an **unstable**-Format NameID (one that
never reached the login-time lookup above, because the Format gate skipped
it) whose *value* nonetheless matches. **This is the tripwire for "my
CC6.8 coverage for SAML users is a false green."**

**Diagnosing "why didn't deprovisioning this user revoke their SAML
access":**

1. Check `yuzu_scim_deprovision_saml_unlinked_total` for a bump at
   deprovision time — it means the user's SAML NameID *value* matched
   their `externalId`, but their IdP's NameID `Format` was never stable
   enough to link (see the warning box above; the most common cause is a
   `transient` default).
2. If that counter is flat, check the three login-time counters for the
   affected window: `yuzu_scim_saml_link_unmatched_total` /
   `_ambiguous_total` mean a stable-Format login *did* attempt to link and
   failed (a stale/duplicate `externalId`, or the IdP's NameID value
   genuinely doesn't match what SCIM pushed); `yuzu_scim_saml_link_lookup_failures_total`
   means the check itself couldn't run that time — correlate with
   Postgres health rather than treating it as a linkage misconfiguration.
3. If none of the four counters moved for the user in question, their
   SAML login was never observed in the relevant window at all — either
   they didn't sign in via SAML in that window, or the observation write
   itself silently failed (see `yuzu_scim_saml_link_write_failures_total`
   above).

**What this does not do.** As with OIDC's D2, both signals are conditioned
on a login-then-deprovision pair actually occurring in the window you're
checking — a flat set of counters means "nothing detected yet," not
"every SAML user is provably linked." Neither signal attributes a
**stable**-Format NameID that never matches any `externalId`, if that fact
is only discovered at deprovision time — that specific case is caught by
the login-time signals above instead (they fire the moment the mismatch
is observable); true deprovision-time attribution of it is deferred to
[#3098](https://github.com/Tr3kkR/Yuzu/issues/3098).

**Rotating your IdP's entity ID strands existing links.** `saml_identity_links`
rows are keyed on `(entity_id, NameID)`. If you rotate
`--saml-idp-entity-id` (e.g. migrating to a new IdP tenant), every
previously-formed link is keyed on the *old* entity_id and will not match
new logins until each affected user signs in again (re-forming the link
under the new entity_id). A deprovision that runs after the rotation but
before a given user's first post-rotation login will not find — and
therefore cannot revoke — that user's pre-rotation-keyed session. This is
an operational caveat of the rotation, not a code defect; plan an
entity_id rotation with a brief window where you also expect to
re-validate SAML session coverage for affected users.

## Reprovisioning a returning employee

If someone leaves and is later re-hired, and your IdP re-issues a `POST`
for the same `userName` rather than reactivating the existing SCIM resource
(some IdP connectors do this after a long enough gap), Yuzu handles it
correctly: `POST` against a `userName` that matches an existing,
**already-deactivated** SCIM-provisioned account revives that account
rather than failing. You do not need to manually clean up or re-create
anything — a `409` conflict is only returned when the `userName` collides
with a **currently-active** account.

## Troubleshooting

- **IdP reports "connection test failed."** Confirm `--scim-enable` is set,
  the server is reachable over HTTPS at the configured base URL, and the
  bearer token in the IdP matches `YUZU_SCIM_TOKEN`/`--scim-token` exactly
  (whitespace/newline differences are a common copy-paste mistake).
- **Every request returns 401.** The bearer token is checked on every
  `/scim/v2/*` call including the discovery endpoints — there's no
  unauthenticated preview. Re-verify the token value configured in the IdP.
- **Provisioning fails with a 400 about `userName`.** Your IdP is almost
  certainly sending an email address as `userName` — Yuzu usernames must be
  a slug (letters, numbers, `.`, `_`, `-` only, no `@`). Remap `userName` to
  a non-email attribute in the IdP's attribute-mapping screen (see
  [Configuring your IdP's SCIM connector](#configuring-your-idps-scim-connector)
  above) and re-run the sync.
- **A user I expected to be deactivated is still active.** Two possible
  causes: (1) the account was never SCIM-provisioned (check
  `provisioning_source` via an admin) — a locally-created account is not
  reachable by SCIM deactivation by design, disable it from the dashboard
  instead; or (2) the account is `role=admin` — either promoted by a
  dashboard admin, or granted admin via [Groups → role mapping](#groups--role-mapping)
  through the configured `--scim-admin-group` — SCIM deliberately refuses to
  touch an account whose role is not `user` (see above). Remove the user
  from the admin group first (which demotes them back to `user`; if they
  are the last protected administrator the demotion is refused and the
  role stays `admin` until another active local administrator account exists AND their role is
  demoted by hand or by a later change that names them), or
  disable the account from the dashboard instead.
- **Deleting/deactivating a group-granted admin via SCIM returns 404.** This
  is expected, not a bug — see
  [Deprovisioning order matters for group-granted admins](#deprovisioning-order-matters-for-group-granted-admins).
  Remove the user from the admin group first; the deactivate/delete call
  then succeeds on the next sync. If that user is the last protected
  administrator the demotion is refused, the role stays `admin` and the
  `404` persists until another active local administrator account exists AND the user's role is
  demoted (by hand, or by a later change that names them; see "The fleet's last
  administrator is protected" and "Group role recompute: when it is
  incomplete" under
  [Deprovisioning and termination](#deprovisioning-and-termination)).
- **A Group change was reported incomplete.** The Group request itself
  succeeded (its membership write committed), but the group's
  `scim.group.created`/`updated`/`deleted` audit row says `recompute=incomplete`
  and a `scim.group.recompute_incomplete` row names the affected members per
  class (first 20 named; the count is exact). A Group change cannot be repaired
  by re-sending it for a member who has LEFT the group: the re-send never names
  that member, so it answers a clean `recompute=complete` while the member still
  holds the role. One remedy per class:
  - **Failed** (`failed=`; a demotion or a promotion): the member's role may not
    be what the groups confer. Check it in Settings > User Management; if it
    should be `user`, demote it with `POST /api/settings/users/{username}/role` with `{"role":"user"}` (the dashboard has no role button. Make the call while signed in as an administrator other than that account, because a self-target answers `403` `self_role_change_blocked`. It needs a cookie session (an account with MFA enrolled also needs a fresh step-up: a proof older than `--mfa-step-up-window-secs`, default 300 s, answers `401` with `meta.mfa_step_up_required`, and a fresh password plus TOTP login counts; an account with no MFA enrolled is not challenged under the default `--mfa-enforcement=optional`; a SAML session gets `403`) or an administrator API token (`Authorization: Bearer` or `X-Yuzu-Token`), which is never challenged for step-up; see [Changing a User's Role](server-admin.md#changing-a-users-role)) and
    revoke its sessions (Settings > User Management > Revoke sessions, or
    `DELETE /api/v1/sessions?username=<name>`, which also needs a fresh MFA step-up
    for a cookie session and, under RBAC enforcement, `UserManagement:Write`
    through an Administrator grant), then look at the store (pool
    waits, a stuck lock holder). If the role is already `user` (the role change
    applied and only the session wipe failed), the role call answers "Role
    unchanged" and does nothing else, so revoke the sessions separately.
  - **Refused demotion** (`refused=`): the last-Administrator guard kept the
    role because no other administrator exists. A second ACTIVE LOCAL account
    whose `role` is `admin` has to exist first: a grant alone, or an SSO-only
    administrator, does not unlock the demotion. Create one (Settings > User
    Management > Add User, which ignores `role`, then `POST
    /api/settings/users/{username}/role` with `{"role":"admin"}`), then demote
    the named member, signed in as the NEW administrator and not as the member,
    with `POST /api/settings/users/{username}/role` with `{"role":"user"}` (the dashboard has no role button. Make the call while signed in as an administrator other than that account, because a self-target answers `403` `self_role_change_blocked`. It needs a cookie session (an account with MFA enrolled also needs a fresh step-up: a proof older than `--mfa-step-up-window-secs`, default 300 s, answers `401` with `meta.mfa_step_up_required`, and a fresh password plus TOTP login counts; an account with no MFA enrolled is not challenged under the default `--mfa-enforcement=optional`; a SAML session gets `403`) or an administrator API token (`Authorization: Bearer` or `X-Yuzu-Token`), which is never challenged for step-up; see [Changing a User's Role](server-admin.md#changing-a-users-role)). Add User has no step-up but the role call can ask for one: if no
    administrator session can pass it, use the break-glass account. See
    [`rbac.md`](rbac.md), "If the guard refuses an action you intend", for that
    exit, and demote or remove the temporary local administrator afterwards from a
    permanent administrator account once one exists (it cannot demote or delete
    itself: `403`, audited as `self_role_change_blocked` for a demotion and
    `self_delete_blocked` for a delete). A later
    change that names the user through another group also re-derives the role.
  - **Undetermined** (`undetermined=`): a read failed, so the role was left
    untouched and it is not known whether an administrator was kept. Check each
    named member's role by hand. A re-send of the Group change works only for a
    member who is still in the group; otherwise demote it with
    `POST /api/settings/users/{username}/role` with `{"role":"user"}` (see above).
  - **Skipped promotion** (`skipped_promotions=`): the promotion was not
    attempted after an earlier write failed. Re-send a `PUT` or `PATCH`; it is
    retried while the member is still in the group. A `DELETE` can never be
    re-sent, so promote by hand if it is needed.
  - **The server stopped mid-request**: see the crash signature table in
    "Known limits of the Group role recompute", item 2. Search the log for
    `membership change committed; role recompute starting` (written at WARN, so
    present at the default level and at `--log-level warn`; also written when a
    group rename flips the admin-group match), and check the roles of the SCIM IDs
    it lists.
- **The server refuses to start after upgrading, on a fresh SCIM
  migration.** As of this release, `scim_resources.external_id` is unique
  (excluding empty values) — a pre-existing duplicate `external_id` (e.g.
  from a stale, uncleaned-up resource) fails the migration and the server
  will not boot. This applies regardless of whether `--scim-enable` is set
  on this boot. See "A duplicate SCIM `externalId` now refuses to boot" in
  [`docs/user-manual/server-admin.md`](server-admin.md#upgrade-notes) for
  the detection query and remediation steps.

## See also

- `docs/auth-architecture.md` "SCIM v2 provisioning" — full technical
  reference (endpoint list, provenance-guard design, storage decision, audit
  actions).
- [REST API Reference](rest-api.md#scim-v2-provisioning) — endpoint-by-endpoint
  wire reference.
- [Authentication](authentication.md) — OIDC/SAML SSO setup (SCIM
  provisions the account; SSO is how the account signs in).
- `docs/security-reviews/scim-groups-role-2026-07-13.md` — security review
  for Groups → role mapping (threat model, provenance-guard extension,
  deprovision-ordering decision).
- `docs/adr/2001-scim-oidc-identity-linkage.md` — the ADR behind
  [SCIM ↔ OIDC identity linkage](#scim--oidc-identity-linkage-federated-token-revocation)
  and [SCIM ↔ SAML identity linkage](#scim--saml-identity-linkage-federated-session-revocation)
  above (design rationale, the D1/D2 forks, the OIDC deny-at-login backstop
  shipped as PR3, and the SAML deny-at-login backstop shipped as PR4b).
