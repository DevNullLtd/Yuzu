# Security review — SCIM v2 Groups→role mapping (SOC 2 CC6.7)

**Date:** 2026-07-13
**Change:** SCIM 2.0 (RFC 7643/7644) **Group** provisioning — an enterprise
IdP (Okta/Entra/OneLogin) can push SCIM Group resources over
`/scim/v2/Groups`, and membership of a configured admin group now grants the
member SCIM-provisioned user the Yuzu **admin** role (`--scim-admin-group`,
`YUZU_SCIM_ADMIN_GROUP`).
**Branch:** `feat/auth-scim-groups-role`
**Control:** SOC 2 **CC6.7** (change-in-role automation — a role grant driven
by an authoritative, auditable IdP signal rather than ad hoc admin action).
Closes `/auth-and-authz` gap-matrix **P1 #7** slice 2 (Groups→role mapping;
slice 1, Users, shipped in PR #2018 — see
`docs/security-reviews/scim-provisioning-2026-07-08.md`).

## What shipped

- **`POST /scim/v2/Groups`** — create a Group (`displayName`, optional
  `members[]`). **`GET /scim/v2/Groups/{id}`** and **`GET /scim/v2/Groups`**
  (list, `startIndex`/`count` pagination, optional
  `filter=displayName eq "..."`). **`PUT /scim/v2/Groups/{id}`** — replace.
  **`PATCH /scim/v2/Groups/{id}`** — add/remove members (RFC 7644 §3.5.2
  PatchOp on the `members` path). **`DELETE /scim/v2/Groups/{id}`** — delete.
  All gated by the same bearer token as Users (`--scim-enable`/
  `--scim-token`), covered by the existing `/scim/v2/` login exemption.
  `Group` is now advertised in `/scim/v2/ResourceTypes` and
  `/scim/v2/Schemas` (schema urn
  `urn:ietf:params:scim:schemas:core:2.0:Group`).
- **`--scim-admin-group` (`YUZU_SCIM_ADMIN_GROUP`)**, default empty — no
  SCIM group grants admin, and every SCIM-provisioned user stays `role=user`,
  identical to the pre-this-slice behavior when unset. Mirrors
  `--saml-admin-group`.
- **Binary admin-group parity, reusing `resolve_role_from_groups`.** Because
  the `auth.db` role model is `admin` | `user` only, the mapping is a
  parity check: a SCIM-provisioned user is `role=admin` **iff** they are
  currently a member of the group whose `displayName` equals
  `--scim-admin-group`. This calls the same `resolve_role_from_groups`
  (`server/core/include/yuzu/server/auth.hpp`) function SAML (#1826) and
  OIDC already use for their own group→role flags — one role-resolution
  function, three callers. Recomputed on user create and on any Group
  create/replace/patch/delete that could change the user's membership of
  the admin group; removal from the group demotes the user back to `user`
  on the next recomputation.
- **The provenance guard extends to role changes, not just deactivate/
  delete.** A role recomputation triggered by a Group mutation only ever
  writes to accounts with `provisioning_source == "scim"` — the identical
  guard the Users slice already uses for deactivate/reactivate/delete/update.
  A Group member whose `value` resolves to a non-SCIM account (a local
  admin, the `--break-glass-user` account) is never role-changed by this
  mechanism, regardless of what a Group's `members[]` list contains.
- **Never elevate beyond the mapping.** Admin is granted only while the user
  is a current member of the one configured admin group — there is no other
  field, attribute, or code path by which a SCIM request can set
  `role=admin`. A compromised or malicious IdP connector can elevate a SCIM
  account only as far as the single group an operator explicitly named in
  `--scim-admin-group`, never past it, and never for an account SCIM did not
  itself provision.
- **404-not-403 anti-existence-oracle behavior extends to Group operations**,
  consistent with the Users slice: a Group operation targeting an unknown or
  guard-rejected resource returns `404`, never a `403` that would confirm the
  resource's existence.
- **New audit verbs:** `scim.group.created`, `scim.group.updated`,
  `scim.group.deleted` (`target_type=Group`), and `scim.user.role_changed`
  (`target_type=User`, records `old_role`→`new_role`, `reason=group`). All
  carry `principal=scim-service`, `principal_role=scim-service`, and follow
  the existing `success`/`failure`/`denied` result vocabulary (not
  `ok`/`error`).
- **New metrics: `yuzu_scim_role_changes_total` and
  `yuzu_scim_role_change_failures_total`.** `yuzu_scim_role_changes_total`
  pairs with `scim.user.role_changed` `success` audit rows.
  `yuzu_scim_role_change_failures_total` is a **hardening-round fix, not
  part of the original slice**: role changes are now audited on **both**
  success and failure (`scim.user.role_changed` `success`/`failure`), and
  the failure case bumps this dedicated metric. **Correction to an earlier
  overclaim in this document:** the existing
  `yuzu_scim_audit_write_failures_total` CC6.8 evidence-integrity control
  does **not** cover this failure mode — it fires when an audit-log *write
  itself* fails after a mutation already succeeded, which is a different
  failure class from a role-apply-failure (the recompute decided on a new
  role but `AuthManager::update_role` did not durably write it). Without
  `yuzu_scim_role_change_failures_total`, a role-apply failure produced
  neither a `failure` audit row nor a metric bump — a real evidence gap,
  now closed by this fix, not by the pre-existing counter.
  `yuzu_scim_requests_total{op,status}` now also counts group operations.
- **Deprovision-ordering decision (deliberate, not a defect).** `deprovision_role_ok`
  (`server/core/src/scim_routes.cpp`) refuses to delete/deactivate an
  account whose `role != "user"` (`404`, no oracle) — this is a
  **demote-before-delete ordering gate**, not a guarantee that a
  dashboard-promoted or group-granted admin stays elevated forever (see
  Model A below for what actually governs role durability). Because
  Groups→role mapping can now put a SCIM-provisioned user at `role=admin`
  through ordinary group membership — not only via a manual dashboard
  promotion, the only way this could happen before this slice — **a user
  who is admin via group membership cannot be SCIM-deprovisioned until the
  IdP first removes them from the admin group**, which demotes them back
  to `user` via the next `recompute_scim_user_role` call and unblocks the
  next deactivate/delete call. This was evaluated against two alternatives
  (special-casing group-granted admins to bypass the role guard; auto-
  demoting on delete before applying the guard) and both were rejected: both
  would reintroduce exactly the risk the role guard exists to prevent — an
  IdP call reaching an elevated account without an explicit, auditable
  demotion step first. The accepted design instead **matches, rather than
  fights, normal IdP offboarding order**: standard Okta/Entra deprovisioning
  already removes a departing employee from all group assignments (including
  any admin group) as part of unassigning the app, ahead of or alongside
  deactivating the user — so no operator-visible friction is introduced for
  a correctly-configured offboarding flow. Documented as required ordering in
  `docs/user-manual/scim-provisioning.md` "Deprovisioning order matters for
  group-granted admins".
- **Model A: IdP group membership is authoritative for a SCIM account's
  role.** A manual (out-of-band) role change on a SCIM-provisioned account
  is reverted to the group-derived role on the next event that recomputes
  that user's membership — a Group `POST`/`PUT`/`PATCH`/`DELETE` resolving
  to that user, or a `User` reprovision — **not** on a plain
  deactivate/delete (blocked outright by `deprovision_role_ok` before any
  recompute runs), and **not** on server restart or on changing
  `--scim-admin-group` itself. Full detail:
  `docs/auth-architecture.md` "SCIM v2 provisioning" § Groups → role
  mapping "Model A"; operator guidance:
  `docs/user-manual/scim-provisioning.md` "Manual role changes to a SCIM
  account are not durable". A manually-promoted admin who is a member of
  no SCIM group is the one case this does not reach — see Residual risks
  below.
- **`displayName`-keyed matching, exact-case, whitespace-trimmed.**
  `--scim-admin-group` is matched against a SCIM Group's mutable
  `displayName` — a byte-exact, case-sensitive comparison
  (`resolve_role_from_groups`); the config value itself is
  whitespace-trimmed at load. `POST`/`PUT /scim/v2/Groups` now reject `409`
  on a `displayName` collision (create) or a rename onto an existing
  `displayName` (replace), and each Group operation enforces a bounded
  maximum on `members[]`.

## Threats considered

- **Compromised IdP using Group push to mint or promote an admin account
  outside the configured mapping.** Closed structurally — admin is granted
  only via `resolve_role_from_groups` parity against the single
  `--scim-admin-group` value; there is no other field or PATCH path that
  reaches `role=admin`.
- **Compromised IdP naming a local principal's SCIM id in a Group's
  `members[]` to elevate or otherwise touch it.** Closed by the provenance
  guard: role recomputation re-checks `provisioning_source == "scim"` at the
  point of the write, exactly as the existing deactivate/reactivate/delete
  guard does — a non-SCIM member in the list is silently skipped for role
  purposes, never mutated.
- **Break-glass / local-admin lockout or elevation via a spoofed or
  malicious Group push.** Closed by the same provenance guard — the
  break-glass account and any locally-created admin have
  `provisioning_source != "scim"`, so no Group-driven role recomputation can
  ever reach them, independent of the account's SCIM-facing id appearing in
  a group's membership.
- **Enumeration via response shape on Group operations.** Closed the same
  way as Users: `404`-not-`403` on an unknown or guard-rejected Group id,
  and the uniform `401` bearer-auth envelope, avoid handing an attacker a
  signal distinguishing "exists but protected" from "does not exist."
- **An admin promoted via group membership evading later deprovisioning
  indefinitely.** Not closed by code — closed by process: the IdP's own
  group removal, which is already the normal first step of Okta/Entra
  offboarding, demotes the user and unblocks deprovisioning on the next sync
  cycle. Recorded as an accepted operational dependency, not a residual
  code gap, in the deprovision-ordering decision above.

## Residual risks (accepted / tracked)

- **Deprovision-ordering constraint on group-granted admins** (see above) —
  accepted as matching normal IdP offboarding order rather than tracked as a
  defect. Operator guidance:
  `docs/user-manual/scim-provisioning.md` "Deprovisioning order matters for
  group-granted admins".
- **Role changes ride the same two-connection `auth.db` posture as the Users
  slice** (`ScimStore` and `AuthDB` are separate `sqlite3` connections onto
  the same file) — no new crash-window is introduced by this slice beyond
  the one already accepted for deactivate/reactivate in
  `docs/security-reviews/scim-provisioning-2026-07-08.md`.
- **No SCIM-specific rate limit on Group operations** — shares the same
  pre-existing, tracked gap as the Users slice (global rate limit only).
- **Binary role model only.** Yuzu's `auth.db` role model is `admin` | `user`
  — Groups→role mapping cannot express finer-grained roles even if a future
  RBAC expansion introduces them; this mirrors the same constraint SAML and
  OIDC group→role mapping already operate under, not a new limitation
  introduced by this slice.
- **Manually-promoted admin with no SCIM group membership (carried from the
  Users slice, not new here).** Model A's revert-on-recompute only fires
  for a user a Group mutation or reprovision actually resolves to. A
  SCIM-provisioned account manually promoted to `admin` that is a member of
  *no* SCIM group is never touched by `recompute_scim_user_role`, so the
  promotion is neither reverted nor is the account SCIM-deprovisionable
  (`deprovision_role_ok` still blocks it) until an operator demotes it by
  hand.

## Storage and code

No new store. Group resources and membership ride the same `auth.db` file
under the existing `"scim"` `MigrationRunner` component the Users slice
already uses (independent of `AuthDB`'s own `"auth_db"` migration track) —
consistent with the ADR-0006 exception note recorded for the Users slice in
`docs/auth-architecture.md` "SCIM v2 provisioning" § Storage.

Full technical reference: `docs/auth-architecture.md` "SCIM v2 provisioning"
§ Groups → role mapping. Operator setup: `docs/user-manual/scim-provisioning.md`
"Groups → role mapping". Wire reference: `docs/user-manual/rest-api.md`
"SCIM v2 Provisioning" § Groups → role mapping.
