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
the next deactivate/delete call succeeds normally.

In practice this is not extra work: standard Okta/Entra offboarding already
removes a departing employee from all their groups (including any admin
group) as part of unassigning the app, before or as part of deactivating
the user. As long as your offboarding flow follows that normal order —
remove from groups, then deactivate/delete — deprovisioning a group-granted
admin behaves exactly like deprovisioning any other SCIM user.

### Recovery and alerting

Deploy these alert rules alongside SCIM Groups → role mapping:

- **`yuzu_scim_role_change_failures_total > 0`** — a role change was decided
  but did not durably apply (an AuthDB write failure during
  `recompute_scim_user_role`). Investigate immediately; the account is
  running with a role that does not match its IdP group membership until
  fixed.
- **A spike in `rate(yuzu_scim_role_changes_total[5m])`** — a sudden burst
  of role changes is the signature of an IdP-side misconfiguration or
  accidental mass group edit (e.g. someone attached the wrong group to the
  Yuzu app, or bulk-edited the admin group's membership), not routine
  churn. Alert on a rate threshold well above your organization's normal
  onboarding/offboarding cadence.
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
  from the admin group first (which demotes them back to `user`), or
  disable the account from the dashboard instead.
- **Deleting/deactivating a group-granted admin via SCIM returns 404.** This
  is expected, not a bug — see
  [Deprovisioning order matters for group-granted admins](#deprovisioning-order-matters-for-group-granted-admins).
  Remove the user from the admin group first; the deactivate/delete call
  then succeeds on the next sync.
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
