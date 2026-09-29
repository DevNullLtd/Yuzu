# ADR-2001 — SCIM ↔ OIDC identity linkage for deprovision (SOC 2 CC6.8)

**Status:** Accepted (rev 3, 2026-08-12 — D1/D2/D3 decided; see "Decisions" below). **PR1+PR2+PR3 all SHIPPED** — the deny-at-login backstop (§4) has landed; see "Known residuals" for the honest scope of what it closes. **PR4a+PR4b (SAML addendum) also SHIPPED** — the SAML analogue of §4/PR3 has landed; see the addendum's item 8 for the honest scope of what it closes on the SAML side. **#3072 (SAML D2 observability) also SHIPPED (2026-08-14)** — the SAML analogue of D2 above, shaped for SAML's single-candidate-NameID model; see the addendum's item 9 for the detector shape and the honest scope of what it can and cannot attribute, and issue #3098 for the one gap it deliberately does not close.
**Authors:** Fraser Jarvis (@fjarvis)
**Date:** 2026-08-12
**Relates to:** ADR-0031 (`0031-engine-principal-store.md`), ADR-0017 (management-group confinement), ADR-0012 (PG store contract), the SCIM v2 provisioning surface, the OIDC stable-principal decision (#1837), and the #2021 SCIM role/provenance guard.

---

## Context

A user deprovisioned through SCIM (`active:false` / `DELETE`) or the dashboard keeps working **API tokens** — SOC 2 CC6.8 (termination) is unmet.

**Surface cause.** All six human-deprovision paths funnel through `AuthManager::remove_user`, which soft-deletes the auth row and wipes MFA but never calls `ApiTokenStore`. `revoke_for_principal(principal_id)` exists and is used correctly by the engine-principal `DELETE` and by `/me` — no user-deprovision path calls it.

**Root cause — two disjoint identities.** A SCIM-provisioned user and their OIDC login identity are **separate `auth.users` rows that are never linked**:

- SCIM provisions `username = <slug>`, `provisioning_source = 'scim'`, stores the IdP's stable id in indexed `scim_resources.external_id`. Stores **no email, no `iss`/`sub`**.
- OIDC login (`auth_routes.cpp:2438`) always mints `username = "oidc:" + iss + "#" + sub`, upserts that row with `external_iss`/`external_sub`, and **never adopts the slug**.
- Tokens mint on `principal_id = session->username`. SCIM users are **SSO-only**, so every token they hold is keyed on the **`oidc:` principal, not the slug**.

So `revoke_for_principal(resource.username)` at the SCIM seam reaches **zero** of a federated user's tokens while reporting success. Closing CC6.8 for the population SCIM governs requires linking the two identities.

### Hard constraints (verified against the code, rev-2)

1. **The `oidc:<iss>#<sub>` principal is the RBAC key and cannot be re-keyed.** `principal_roles`, group reconcile (#1832), JIT eligibility, and the audit trail key on it (`rbac_store.cpp:188-195`). "Adopt the slug at login" orphans every grant. **Rejected.**
2. **No join key exists in the data today.** `externalId` (SCIM) and `sub` (OIDC) are both stable/IdP-asserted but *not asserted equal*, and IdP-dependent: Okta typically `sub == externalId`; **Entra typically not** (`externalId` = AAD object id, which rides the token as the `oid` claim, **not** `sub`). Email↔email unavailable (SCIM stores none; OIDC `email_verified` not captured).
3. **Only IdP-asserted, stable claims may enter the trust path.** `sub` and `iss` are parsed and validated fail-closed today (`oidc_provider.cpp:331-419`: non-empty, ≤255, no control bytes — the #1837 hardening). **`oid` is NOT parsed or validated anywhere today** (no field on `IdTokenClaims`, no parser branch). Using it as the Entra join is therefore **new work delivered by this ADR** (§ Deliverables), not an existing toggle, and admitting a new claim to the trust path must replicate the `sub` validation exactly — else it becomes an audit-injection / malformed-key vector. `email`/`preferred_username`/`name` are mutable display fields — **forbidden as a join key** (a mutable join is an auth bypass).
4. **Provenance guard interaction (stated precisely).** The link + cross-identity deprovision are gated to `provisioning_source='scim'`, `role='user'` **on the slug**. Local-admin and break-glass accounts are genuinely unreachable (non-`scim` provenance ⇒ no `external_id` ⇒ no link forms). But the **linked `oidc:` principal's own role is not consulted and MAY be admin** — a federated identity elevated by standing grant or group→role. Revoking a federated admin's tokens on termination is the *intended* CC6.8 behavior and must be **audited as an admin revoke**; the earlier draft's "fires only for role=user" was false about the *target* of the revoke and is corrected here.
5. **Single-issuer precondition.** `ScimStore::find_by_external_id` is a global `WHERE external_id=$1` with **no issuer predicate**, and `scim_resources` carries no `iss`. Link formation is sound **only under a single trusted OIDC issuer** (Yuzu's current config). Any future multi-IdP OIDC MUST partition the externalId space by issuer (add `iss` to the SCIM resource or the match) before this design is safe. **Binding precondition, not prose.**

### The good news

`auth.users` already carries `external_iss`/`external_sub`/`provisioning_source`; `scim_resources.external_id` is indexed. What is missing is forming/recording the link and a policy for which claim forms it.

---

## Decision

A **durable, login-established, IdP-asserted-claim link** between a SCIM slug and the OIDC principal(s) that authenticate as that person, with deprovision acting across the link. Reconciliation idea unchanged from rev 1; the mechanics below are corrected per review.

### 1. Join key: configured, IdP-asserted claim, default `sub`, allow-list `{sub, oid}`
`--oidc-scim-link-claim` (default `sub`; boot **rejects** anything outside `{sub, oid}`). Okta: default. Entra: `oid` (which this ADR adds to the parser with `sub`-equivalent fail-closed validation). No shared id ⇒ no link forms ⇒ see D2.

### 2. Link recorded at login, from authenticated data only — fail-closed on ambiguity
**`scim_resources.external_id` is indexed but NOT unique today** (`scim_store.cpp:43,49`), and `find_by_external_id` takes `LIMIT 1` — so a duplicate externalId would let link-formation pick a row arbitrarily and **mis-link an OIDC identity to the wrong SCIM user, revoking the wrong principal** (codex-sol plan-review BLOCK, 2026-08-12). Two mandatory mitigations, belt-and-braces:
- **Link formation forms a link only when EXACTLY ONE active SCIM resource matches** the link-claim value. Zero matches → no link (normal). More than one → **no link**, never an arbitrary pick — `ScimStore::find_unique_active_by_external_id` folds both zero and more-than-one matches into `nullopt`. This is the load-bearing safety and works on existing data even before the index below lands.
- **Add a partial-unique index** on `external_id` where non-empty (the correct SCIM posture, shipped as `scim_resources_external_id_uniq` in migration v3). The migration **detects pre-existing duplicates and fails closed** (refuses to open, per the store's ADR-0012 posture) rather than silently skipping index creation — a store that opens with a violated uniqueness assumption is exactly the mis-link hazard.

**Amendment (2026-08-12, post-implementation): no separate "ambiguity signal" is wired, and this is correct, not a gap.** An earlier draft of this section additionally called for incrementing a dedicated `external_id`-ambiguity counter on the `find_unique_active_by_external_id` more-than-one-match branch, folding it into the D2 detector family. That branch is now **structurally unreachable in ordinary operation**: the partial-unique index makes a second active row sharing a non-empty `external_id` impossible to create in the first place (an `INSERT`/`UPDATE` that would produce one raises `unique_violation` and the write fails, surfaced through this store's existing db-failure return contract on `create_resource`/`update_resource` — an operator-visible failure at write time, not a silent success), and a database that somehow already violated the constraint before the index existed fails the **migration** at boot (see the "duplicate externalId now refuses to boot" upgrade note in `docs/user-manual/server-admin.md`) before any login-time ambiguity could ever be observed. The migration-time fail-closed boot refusal and the insert-time `unique_violation` are together a **strictly stronger** mitigation than a login-time signal would have been — they prevent the ambiguous state from ever existing, rather than detecting it after the fact — so the more-than-one-match branch in `find_unique_active_by_external_id` is retained purely as defense-in-depth (belt-and-braces against the index ever being bypassed, dropped, or absent on a downgrade) and deliberately does not emit its own metric. Do not add one under a future refactor without first checking whether the index is still in force; this note exists so that omission is never mistaken for an oversight. This resolves consistency-auditor finding C2.

On successful OIDC login whose link-claim value matches **exactly one** active SCIM `external_id`, record a durable link in a **dedicated `identity_links` table owned by `ScimStore`** (schema `scim_store`; born-on-PG per ADR-0012). Keyed `(iss, sub)` **unique**, with a **secondary index on `scim_id`** (deprovision looks up by `scim_id`, which the `(iss,sub)` key does not serve), carrying `linked_at`. The link write is **fail-OPEN** — a failed write never fails the login (the missing link is caught by the D2 detector). A dedicated table is mandatory, not a preference: the model is **many** `(iss,sub)` per `scim_id`, which a single `external_iss/sub` column pair on the slug row cannot represent (and those columns do not exist on `scim_resources`) — the column-overload alternative is **withdrawn as infeasible**.

### 3. Deprovision acts across the link, credentials-first, fail-closed, orchestrated ABOVE the stores
SCIM `active:false`/`DELETE` and dashboard delete resolve slug → `scim_id` → linked `(iss,sub)` → principal strings, and for **each** principal (slug + every linked `oidc:` id) revoke tokens (`revoke_for_principal`) and sessions **before** marking the account inactive. This **reorders** today's `deactivate()` (which does `remove_user` first) — safe, all ops idempotent, and it matches the engine-principal `DELETE` ordering. On any `revoke_for_principal → unexpected`, do not report clean success: SCIM `500` so the IdP retries; audit `partial`; metric `result=partial`; the did-not-persist-vs-zero-tokens distinction preserved per principal. **The deprovision orchestrator is credentials-FIRST and must NOT reuse `session_revoke_fn`** (`server.cpp:15346`), which is session-first and carries `caller=self|admin` semantics — a distinct helper over the per-principal `revoke_for_principal` + `invalidate_user_sessions` primitives (codex-sol plan-review, 2026-08-12).

**Lock/pool discipline (the real hazard, per architect):** the three stores share one bounded `pg_pool_`. The orchestration lives **above** the stores — it calls each store's public method in sequence and **never holds one store's pool lease while calling another** (a nested second lease from the same pool can exhaust/deadlock it, `api_token_store.hpp:257`). `AuthManager::mu_` stays a leaf, never held across a store/DB/bus call (unchanged house discipline). Acquisition order to hold: resolve links (ScimStore) → revoke tokens (ApiTokenStore) → revoke sessions (AuthManager) → mark inactive (AuthManager) → SCIM mirror (ScimStore), each self-contained.

### 4. Deny-at-login backstop (own PR — see Delivery) — SHIPPED (PR3)
An OIDC login whose linked SCIM resource is deprovisioned is **denied** — fail-CLOSED — emitting the **identical `?error=sso_failed` redirect** as the existing token-exchange-failure branch (`auth_routes.cpp:2422`), with a server-side `auth.oidc.deprovisioned_denied` audit and the `yuzu_auth_oidc_deprovisioned_denied_total` counter. This closes the re-login-mints-fresh-tokens window that eager revoke alone leaves — refusing a login against an **already-completed** deprovision, the dominant case, outright. Architecturally decoupled from §3 (different site, opposite failure direction) → separate PR.

Implemented as `ScimStore::linked_resource_active(iss, sub)`, a single fused `identity_links` ⋈ (LEFT JOIN) `scim_resources` query, so an **orphaned link** — the linked `scim_resources` row hard-DELETEd by a SCIM `DELETE` (`identity_links` is not FK-cascaded) — is denied exactly like an explicitly deactivated one, rather than reading as "no link" (which an INNER join would have produced) and letting the deprovisioned identity re-authenticate. Store-unavailable (the query itself cannot be answered) also denies, fail-closed. The decision is called from two sites in `/auth/callback`: a **primary** check before any session/link mint, and a **post-mint re-check** that invalidates a just-minted session if the identity was deprovisioned concurrently — see "Known residuals" below for exactly what this does and does not close.

### 5. Single shared principal-string helper (mandatory)
The `oidc:<iss>#<sub>` string is hand-built at two sites today; the resolver would be a third. A drift in the format silently misses every token — the exact "reported success, revoked nothing" failure. **Require one `oidc_principal_id(iss,sub)` helper**; the resolver returns raw `(iss,sub)` rows and this helper builds every principal string. Do **not** widen `session_revoke_fn` (it carries `caller=self|admin` metric semantics) — add a resolver over the existing per-principal revoke primitive.

---

## Decisions (accepted 2026-08-12, @fjarvis)

- **D1 → preserve #2021 for the slug's account state, do NOT auto-revoke a manually-elevated federated admin on the IdP's say-so, and make the refusal LOUD** — a `kCritical` audit + `yuzu_scim_deprovision_role_refused_with_active_link_total`. The silent hole becomes a paged alert a human resolves; #2021's IdP-compromise protection is preserved. (Horn (b) below.)
- **D2 → record every OIDC login's attempted link-claim value** (a durable `(iss, sub, claim_name, claim_value)` observation, written regardless of match) so a deprovision can surface a should-have-matched candidate under a mis-configured `--oidc-scim-link-claim`. (Horn (a) below.)
- **D3 → PR1+PR2 ship together, PR3 (deny-at-login) separate.** Token-revoke seam + full linkage as one PR (CC6.8 cell moves only when linkage lands); the fail-closed login-path change isolated in its own PR.

The full analysis of each fork is retained below for the build team.

## The forks, analysed (D1/D2 decided above)

**D1 — the #2021 provenance fork (security F1, HIGH).** When a SCIM slug was elevated to admin *outside* SCIM and the IdP sends a deprovision, `deprovision_role_ok` 404s to protect that admin from a racing/compromised IdP (#2021). Post-linkage this silently leaves the terminated person's *federated* tokens live and never arms deny-at-login. Two horns:
  - **(a) Auto-revoke the linked federated identity anyway** — termination-complete, but reopens what #2021 defends (a compromised IdP can kill an admin's access via SCIM).
  - **(b) [recommended default] Preserve #2021 for the slug's account state, do NOT auto-revoke the federated admin on the IdP's say-so, but make it LOUD** — a `kCritical` audit + `yuzu_scim_deprovision_role_refused_with_active_link_total` so a human resolves the termination deliberately. This closes the *silent* half of F1 (the hole becomes a paged alert, not an invisible gap) without letting an IdP unilaterally revoke an admin. The residual (a genuine termination of a manually-elevated federated admin needs one manual step) is acceptable and auditable.

**D2 — the fail-loud detector (security F2, HIGH).** The rev-1 fail-loud predicate is unrealizable — the slug and `oidc:` rows are disjoint, so "logged in but link never formed" is indistinguishable from "never logged in," and that is exactly the Entra/mismatch silent-under-revocation case. To make it detectable requires capturing new data. Options:
  - **(a) [recommended] Record every OIDC login's *attempted* link-claim value** (a row per `(iss, sub, claim_value_seen, claim_name)` regardless of match). A deprovision of externalId `E` can then ask "did any login present a candidate that should have matched `E` under a different configured claim?" → a real, actionable "your `--oidc-scim-link-claim` is wrong for this IdP" signal. Cost: one more durable table + a login-time write.
  - **(b) Capture `email`/`email_verified` on both sides** as a fallback correlator. Larger SCIM-schema change; weaker (email is mutable).
  - **(c) Accept a weaker CC6.8 claim** for mismatched-IdP deployments and state the limitation, no detector. Cheapest, least honest.
  Without one of these, the CC6.8 completeness claim for the federated population is unproven — which is the reason this went ADR-first.

---

## Consequences

- **CC6.8 residual, stated honestly:** after deprovision, a previously-issued API token may keep validating for up to **~60s** (the `ApiTokenStore` validate-cache TTL, `api_token_store.hpp:787`; MCP stream sessions carry the same), plus the irreducible IdP→SCIM lag before deprovision fires. Cookie sessions are erased immediately. Deny-at-login (§4, shipped) refuses re-login against an already-completed deprovision outright, and narrows — via a post-mint re-check — but does not by construction eliminate, a login racing an in-flight deprovision (see "Known residuals" for the precise, deliberately-scoped guarantee). The guarantee is "revoked within ~60s of the deprovision reaching Yuzu, and no new access thereafter for a completed deprovision," not "instant" and not an absolute guarantee against every in-flight race.
- **New availability coupling, stated honestly (PR3 governance fold D1):** the deny-at-login check (§4) is fail-**CLOSED** on a `ScimStore`/Postgres query failure — once `--scim-enable` is set, OIDC login availability is now hard-coupled to `ScimStore`'s live query path. A `ScimStore`/Postgres outage therefore denies **every** OIDC login fleet-wide, including a user who was never SCIM-linked at all, not only an actually-deprovisioned one. This is the correct tradeoff — a login whose deprovision status cannot be checked is treated as unsafe, consistent with the born-on-PG fail-closed posture (ADR-0012 §1) — but it is a real new availability dependency and must be operator-visible, not left implicit in metric-doc prose; see `docs/user-manual/scim-provisioning.md`'s operator runbook for the blast-radius note (password login is unaffected — this coupling is OIDC-only).
- **Deliverables (new work this ADR authorizes):** `oid` claim parse + `sub`-equivalent validation; `identity_links` table (ScimStore, `(iss,sub)` unique + `scim_id` index, no-prune-by-decision — orphan links from a claim-config change accumulate but only ever cause safe over-revoke); `--oidc-scim-link-claim` flag; the shared `oidc_principal_id` helper; a principal-set resolver; the deprovision reorder; new audit verbs + metrics; plus whichever D1/D2 options are chosen.
- **INV-31-3 not crossed:** `identity_links` has one owning store (ScimStore), method-mediated — a future engine/core split stays clean.
- **Delivery (architect recommendation, reconciled with the "A+B together" intent):** three reviewable PRs — **PR1** per-principal revoke at the deprovision seams (`{slug}` only, forward-compatible set-resolver); **PR2** linkage (`oid`, `identity_links`, resolver, D2 detector); **PR3** deny-at-login (D1 handling + §4). **All three have now shipped.** The CC6.8 compliance cell may only be updated to "complete for federated users" **after PR2** — PR1 alone must not touch it, or it overstates. If you want a single PR per your earlier call, PR1+PR2 can merge together; PR3 (login-path, fail-closed) is best kept separate for blast-radius.

### Known residuals

- **The ~60s validate-cache window** (see Consequences above) — stated honestly, not treated as fixed by this ADR.
- **A manually-elevated federated admin's tokens are not auto-revoked (D1)** — by design, a human step; see D1 above.
- **Login-mid-deprovision TOCTOU — narrowed by PR3, not fully eliminated. This is a deliberate design decision, not an oversight; state the guarantee precisely, never as "the race has nothing left to win."** PR1+PR2 close the *deprovision-time* revoke gap. §4/PR3 (shipped) then refuses a login whose linked SCIM resource is **already** deprovisioned — the dominant case, and it is fully closed: a re-login after a completed deprovision cannot mint a fresh credential, full stop.
  What PR3 does **not** eliminate outright is the narrower **in-flight-deprovision** race: a login that authenticates and forms/refreshes an `identity_links` row for `(iss, sub)` strictly **between** the primary deny-at-login check and the session mint — concurrently with a deprovision's `set_active(..., false)`/delete write landing in that same window — can still walk away with a session minted before the deprovision was visible to the check that ran. PR3 **self-heals** this window with a **post-mint re-check**: immediately after minting, `oidc_login_denied_deprovisioned` is called again, and if the identity has since flipped to deprovisioned, the just-minted session is invalidated and the login is denied before any cookie reaches the browser (`AuthManager::invalidate_user_sessions`). This closes the window to everything except a **microsecond check-then-mint gap** that remains theoretically possible between the re-check's own read and the response being sent.
  **That microsecond gap is deliberately not closed by lock-serialization.** Holding a lock across the login's check→mint sequence and the entirety of a concurrent deprovision would require a cross-store lease held over a sibling-store call (`ScimStore` across `AuthManager`'s session mint), which this codebase's store discipline (§3 above; `AuthManager::mu_` and the shared `pg_pool_` leases) treats as a deadlock hazard, not a hardening opportunity — see §3's "never hold one store's pool lease while calling another." **The residual bound differs by credential kind — do not collapse the two.** (a) An **API/MCP token** minted or already held during the race is caught by the existing **~60s `ApiTokenStore` validate-cache window** above: even a freshly-minted token stops validating within that bound once the underlying revoke lands. (b) A **slipped session is not on the same clock.** `AuthManager::validate_session` re-checks only the session's own expiry/idle timeout on every request — it does **not** re-query SCIM-linked deprovision state — so a session that does slip through this race remains valid for up to the **session's own TTL** (the absolute `kSessionDuration`, 8h by default, or the shorter `--session-inactivity-secs` idle timeout when configured), not ~60s. It is cut short early only if a *subsequent* deprovision call happens to land against the same identity — which is not guaranteed: an IdP does not necessarily re-send a deprovision call for a resource it already believes is deactivated. Stating the session residual as "~60s" or as reliably self-healed by a next deprovision pass overstates the guarantee.
  **The honest guarantee, stated precisely:** re-login against an already-completed deprovision is refused, unconditionally. A login racing an in-flight deprovision is refused in the overwhelming majority of timings and self-heals via the post-mint re-check in the remainder; a vanishingly narrow, deliberately-unclosed microsecond window remains, bounded by the ~60s cache TTL for API/MCP tokens and by the session's own TTL (not ~60s) for a slipped session, not eliminated by construction. **Do not describe this as "the race has nothing left to win" or as fully closing the TOCTOU** — that overclaims what a lock-free, cross-store design can guarantee. Operationally the window is additionally bounded by ordinary IdP-to-Yuzu SCIM propagation latency (typically seconds to low minutes, IdP-dependent), not unbounded.
  **Forward caveat — single-primary Postgres reads assumed.** The guarantee above is sound only because Yuzu's Postgres deployment is single-primary today: every `linked_resource_active` read lands on the same primary a deprovision write just landed on, so there is no replica-lag window beyond the microsecond check-then-mint gap already described. If read-replica routing is ever introduced for `ScimStore`, a check could read a stale, not-yet-replicated `scim_resources.active` value, and this residual would widen from a microsecond window to ordinary replica lag — revisit deny-at-login's guarantee at that point. Not a current defect; single-primary is the shipped, verified configuration.
- **Orphaned links (the `scim_resources` row was hard-DELETEd by a SCIM `DELETE`) are handled, not a gap.** `linked_resource_active`'s LEFT JOIN surfaces a deleted-but-still-linked `identity_links` row as `active == nullopt` (an INNER join would instead have silently treated the now-rowless join as "no link" and let the deprovisioned identity re-authenticate). The deny decision then distinguishes two orphaned sub-cases: if an **active resource now exists for the login's externalId** (`find_unique_active_by_external_id`), the identity was DELETE'd and re-`POST`ed under a new `scim_id` — a returning employee — so the login **proceeds** and the imminent `link_oidc_login_to_scim` repoints the stale link; if **no** active resource exists, it is genuinely deprovisioned and is **denied** (like an explicitly deactivated one). This reprovision distinction is scoped to the orphaned branch only — the `external_id` unique index guarantees an explicitly-deactivated (row-present) resource can have no active same-externalId sibling. Denying orphaned links unconditionally (the pre-fix behaviour) would permanently lock out a returning re-provisioned employee.

## SAML ↔ SCIM identity linkage (PR4a addendum, accepted 2026-08-13)

This ADR's title and body above are OIDC-specific by construction (§5's
`oidc_principal_id`, the `identity_links` table, `--oidc-scim-link-claim`).
**PR4a extends the same closing argument to SAML**, delivering the SAML
analogue of PR1+PR2 (link formation + deprovision-time revoke). SAML
deny-at-login — the analogue of §4/PR3 above — is **PR4b (#3066), SHIPPED**
(2026-08-13, see item 8 below).

**Why a SAML gap exists at all.** Exactly the same root cause as the OIDC
case: prior to PR4a, a SAML login minted a session keyed on the raw NameID
(`AuthManager::create_saml_session`, the "#1837 fast-follow" comment it
replaced), with no link ever recorded to the SCIM resource that provisioned
that person. A SCIM deprovision therefore reached zero SAML sessions for a
federated user's identity while reporting a clean success — the same
silent-under-revocation shape §"Context" above describes for OIDC tokens,
here for SAML sessions.

**1. The stable principal: `saml:<entity_id>#<NameID>`, one builder.**
`saml::saml_principal_id(entity_id, name_id)` (`server/core/src/
saml_principal.hpp`) is `"saml:" + entity_id + "#" + name_id` — the SAML
mirror of §5's `oidc_principal_id(iss, sub)`, for the identical reason: a
NameID is only guaranteed unique *within* one IdP, so a bare NameID is unsafe
as a durable session/RBAC key the moment more than one IdP (or, before this
addendum, a future multi-tenant deployment) could assert it. Every
construction site — the session-mint site (`AuthManager::
create_saml_session`) and the deprovision-time resolver
(`deprovision_revoke.cpp`) — routes through this one function; a hand-built
copy at either site would silently drift and miss sessions on revoke,
exactly §5's stated failure mode.

**2. Session-key / display-name split.** `create_saml_session`'s `username`
(the authorization/audit/revoke key) becomes the stable principal;
`display_name` stays the raw NameID (rendering only). This is the SAML
mirror of the OIDC session's own username/display split.

**3. The NameID-Format contract (architect codex-sol plan-review BLOCK,
2026-08-12).** A NameID is a safe join key against a SCIM `externalId`
**only when it carries a STABLE Format AND its value equals that
`externalId`** — an assertion's `<NameID Format="...">` attribute is read
(`SamlAssertion::name_id_format`, from the same XSW-verified node as the
NameID itself) and gated: a link forms only for
`urn:oasis:names:tc:SAML:2.0:nameid-format:persistent` or the SAML 1.1
`urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress`
(`saml::is_linkable_name_id_format`). `transient` (re-minted per login by
design), `unspecified`, and a missing Format are all treated conservatively
as **not linkable** — Yuzu never normalizes a NameID into a linkable shape.
This is a configuration contract on the operator, stated explicitly: **the
operator MUST configure their IdP to emit a NameID that is both a stable
Format and numerically equal to the externalId SCIM provisions that person
with.** Yuzu's role is to reject an unacceptable Format outright, never to
coerce one. A stable-Format NameID that simply doesn't match any
`externalId` — or a deployment left on `transient` — forms no link; the
login still succeeds (this is not a login-time authorization gate, only a
linkability gate), but that identity is unlinkable and therefore
**unrevocable via SCIM deprovision** — the documented residual below.

**4. Single-IdP precondition — stronger than the OIDC case.** §"Hard
constraints" constraint 5 above requires the OIDC side to reason about
multiple possible issuers sharing one `externalId` space; SAML does not face
that question in the same way, because Yuzu already requires exactly one
pinned IdP cert + one pinned `--saml-idp-entity-id`
(`SamlProvider::is_enabled()`), and `SamlProvider::validate_response`
verifies the assertion's signed `<saml:Issuer>` equals that pinned
`entity_id` before anything downstream ever sees it. One pinned IdP is what
makes a bare NameID→`externalId` match safe by construction here, without
needing an `iss`-partitioned `externalId` space the way a future multi-IdP
OIDC configuration would.

**5. `saml_identity_links` (ScimStore migration v4).** A dedicated table —
deliberately **not** a generalization of §2's `identity_links` (keeps this
addendum off PR3's OIDC schema surface) — keyed `(entity_id, name_id)`
unique, secondary-indexed on `scim_id` (the deprovision lookup direction).
Link formation reuses the same `find_unique_active_by_external_id`
exactly-one-active-match rule §2 established for OIDC (zero matches: no link,
normal; more than one: no link, never an arbitrary pick). The write is
fail-**open** — a write failure never fails the login, mirroring §2's OIDC
contract exactly.

**6. Deprovision revokes the SAML session — and any token minted under it.**
`resolve_deprovision_principals` (§3's resolver) gained a second pass:
`saml::saml_principal_id(entity_id, name_id)` for every row
`ScimStore::saml_links_for_scim_id(scim_id)` returns, fail-**closed** on that
call's own `nullopt` (the identical contract §3 gives the OIDC pass). SAML
has no *separate* token-mint path — the only session-mint call site keyed on
a `saml:` principal is `create_saml_session` — but the revoke functions
(`revoke_for_principal` et al.) are principal-agnostic: any token that was
minted with a `saml:` principal as its owner (e.g. via the HTMX
settings-page token-create route, which stamps the calling session's
username onto the token regardless of that session's auth source) is
revoked right alongside the session when its `saml:` principal is resolved
into the revoke set. In practice this means a SAML deprovision's dominant
observable effect is the session teardown, since the SAML login flow itself
never mints a token — but it is not the *only* thing revoked for that
principal.

**7. The residual, before PR4b — retained here as history.** Before PR4b
shipped, a SAML identity whose linked SCIM slug was already deprovisioned
was not refused at `/saml/acs`: a person who still held a valid, signed
assertion from the IdP could re-authenticate after their SCIM deprovision
and mint a fresh session, correctly revoked again on the *next* deprovision
pass but live in the meantime — precisely the window §"Known residuals"
describes for OIDC's PR3 gap. Item 8 below records what PR4b closed and, as
honestly as §"Known residuals" does for OIDC, what it did not.

**8. Deny-at-login backstop — PR4b (#3066), SHIPPED 2026-08-13. The SAML
analogue of §4/PR3 above, same shape, same fail-closed posture.**
`ScimStore::saml_linked_resource_active(entity_id, name_id)` resolves the
identity in one query — a LEFT JOIN from `saml_identity_links` to
`scim_resources`, reusing §4's `LinkedResourceState` tri-state shape
byte-for-byte — and, exactly like §4's `linked_resource_active`: an INNER
join would collapse an orphaned link (the `scim_resources` row hard-DELETEd,
`saml_identity_links` not FK-cascaded) into "no rows," which reads as "no
link" and would let a fully-deprovisioned identity re-authenticate — the
LEFT JOIN closes that.

`saml::saml_login_denied_deprovisioned(scim_store, entity_id, name_id)`
(`saml_scim_link.{hpp,cpp}`) is the single pure decision function both call
sites in `/saml/acs` share, mirroring §4's `oidc_login_denied_deprovisioned`
structure exactly:

1. **Primary check**, immediately after `saml_principal` is computed and
   strictly **before** any mutation below it (link formation, session mint)
   — a denied login leaves no side effect behind.
2. **Post-mint re-check**, run again immediately after
   `create_saml_session` and strictly **before** the `Set-Cookie` header is
   written. If a concurrent SCIM deactivate/DELETE landed in the window
   between the primary check and the mint, this re-check catches it: it
   calls `AuthManager::invalidate_user_sessions` on the session just minted
   and denies — self-healing the check-then-mint race the identical way §4
   does for OIDC, without holding a cross-store lease over the mint.

Unlike the OIDC side, there is no separate `link_claim_value` parameter —
SAML has exactly one join key (the NameID itself, see item 3 above), so the
orphaned-branch reprovision check (`find_unique_active_by_external_id`)
always resolves against `name_id`. The reprovision distinction is scoped to
the orphaned branch only, for the identical reason §4 states: the
`external_id` unique index means an explicitly-deactivated (row-present)
resource can have no active same-externalId sibling, so the deactivated
branch stays an unconditional deny.

Both deny sites emit the **byte-identical** `/login?error=saml` redirect
every other SAML failure branch in `/saml/acs` uses (no "deprovisioned"
wording reaches the browser — no oracle, mirroring §4's U6 fix exactly), a
server-side audit row `auth.saml.deprovisioned_denied` (`result=failure`,
principal = the `saml:<entity_id>#<NameID>` principal), and increment the
pre-seeded counter `yuzu_auth_saml_deprovisioned_denied_total`. `detail`
distinguishes the two denial causes the same way §4's OIDC row does:
`reason=linked_scim_resource_inactive;scim_id=<id>` when an actually
resolved (deactivated or orphaned-not-reprovisioned) SCIM resource drove the
denial, versus `reason=scim_store_unavailable` (no `scim_id`) on the
fail-closed store-unavailable path. On the post-mint re-check path only,
`detail` additionally carries `;post_mint_recheck=true;sessions_invalidated=
<N>`, and `;db_persisted=false` if the session-revoke write itself did not
persist.

PR4b inherits the `--scim-enable` gate for free: `/saml/acs` reads the same
gated `AuthRoutes::scim_store_` member the primary/deprovision SCIM routes
already null-check, so with SCIM off `saml_login_denied_deprovisioned`
receives a null store and unconditionally proceeds — no feature-off SAML
login outage, and no new availability coupling beyond the one §4 already
introduces for OIDC while `--scim-enable` is on.

**The honest guarantee, exactly as scoped as §4's for OIDC.** Deny-at-login
**fully closes** the dominant case for SAML too: a re-login against an
**already-completed** deprovision is refused, unconditionally. It
**narrows, but does not eliminate by construction**, the same
in-flight-deprovision race §4 describes for OIDC, for the identical
reasons (the cross-store-lock deadlock hazard, §3 above) — bounded by the
post-mint re-check in the overwhelming majority of timings, with a
microsecond check-then-mint gap remaining theoretically possible. SAML has
no API/MCP token validate-cache to bound a slipped session against (SAML
mints no tokens); a session that does slip through is bounded only by the
session's own TTL, the identical residual §"Known residuals" states for a
slipped OIDC session. **Test coverage caveat, stated once and applying to
both providers' ACS/callback wiring:** there is no mock-IdP integration
harness in this codebase exercising a live `/saml/acs` (or `/auth/callback`)
round-trip end to end — `saml_login_denied_deprovisioned` and
`oidc_login_denied_deprovisioned` are each covered by direct unit tests
against the decision function (`test_saml_scim_link.cpp`,
`test_oidc_scim_link.cpp`), and the two call sites' wiring into the route
handler (ordering relative to link formation/mint/`Set-Cookie`, the audit
detail construction, the redirect) is verified by code inspection rather
than an end-to-end test exercising a real assertion/token exchange. This is
an existing, not newly-introduced, test-coverage limitation shared by both
providers' deny-at-login backstops.

**Residual — pinned-trust-anchor rotation orphans links (both providers).**
Identity links are keyed on the pinned IdP identifier — `entity_id` for SAML,
`iss` for OIDC — because that identifier is part of the principal identity
itself (it is what keeps a `saml:` and an `oidc:` principal from colliding on
a shared NameID/subject). Rotating `--saml-idp-entity-id` (or the OIDC
`--oidc-issuer`) therefore leaves every existing link row keyed on the *old*
value, so a lookup under the new identifier returns zero rows and reads as
"no link → proceed": the deny-at-login backstop does not fire for an
already-deprovisioned identity logging in under the rotated identifier, and
it **cannot re-arm itself via SCIM** (a link re-forms only against an *active*
resource, and a deprovisioned resource is inactive — so re-running SCIM
deprovision does nothing). Within the single-pinned-IdP designed envelope (one
stable identifier) the control holds; a rotation is re-establishing the trust
anchor, and across it the operator relies on the **primary** termination
control — the IdP ceasing to assert for a terminated user. This is a deliberate
residual of the single-pinned-IdP linkage model, not a code gap the deny logic
can close without abandoning the `entity_id`/`iss`-scoped link key. Full
treatment (mechanism, why re-deprovision does not help, the symmetric OIDC
case) is in `docs/auth-architecture.md` → "SAML ↔ SCIM identity linkage",
"Residual — rotating the pinned trust anchor orphans existing links". Surfaced
independently by the PR4b governance unhappy-path review and a Hermes
access-review pass.

**9. SAML D2 observability — #3072, SHIPPED 2026-08-14.** §"D2" above
(under "The forks, analysed") notes SAML's version of D2 was, until now, a
stated non-gap rather than a gap: OIDC's D2 exists to catch a misconfigured
`--oidc-scim-link-claim` among several candidate claims (`sub`/`oid`), and
SAML has no such knob — exactly one candidate join key, the NameID. That
reasoning is still correct as far as it goes, but it left a real, distinct
gap unaddressed: nothing recorded *whether* a SAML login had even been
attempted for an `externalId` that later turned up unlinked at
deprovision. #3072 closes that, with a detector shaped for SAML's
single-candidate model rather than a re-skin of OIDC's multi-candidate one.

A new `saml_login_observations` table (`ScimStore` migration v5, keyed
`(entity_id, name_id, name_id_format)` unique, secondary-indexed on
`name_id`) records every SAML login's NameID observation — including an
unstable-Format one — **unconditionally**, before the NameID-Format
linkable gate in `link_saml_login_to_scim` runs. This is the SAML analogue
of §"Decisions"' D2 bullet ("record every OIDC login's attempted
link-claim value... regardless of match"), adapted to a single candidate:
there is nothing to choose among, but there is still a durable "a login
was attempted under this value" fact worth keeping. `name_id_format` is
part of the uniqueness key specifically so a later stable-Format login
cannot silently overwrite an earlier unstable-Format observation of the
same value.

`link_saml_login_to_scim` now returns a typed `SamlScimLinkOutcome`
(`not_linkable` / `linked` / `no_active_match` / `ambiguous_match` /
`lookup_store_error` / `link_write_error`) instead of `void`, built on a
new store-layer lookup, `find_unique_active_by_external_id_checked`, that
distinguishes `no_match`/`ambiguous`/`store_error` where the pre-#3072
`find_unique_active_by_external_id` collapsed all three into one `nullopt`
(that plain function is now a byte-compatible wrapper over the checked
one — every existing caller keeps its exact prior behaviour). Every
`SamlScimLinkOutcome` value is still a **proceed** outcome for the login —
login-time linking remains fail-open by contract, unchanged from PR4a;
`no_active_match` and `ambiguous_match` each drive a login-time,
observe-and-proceed audit row (`auth.saml.link_unmatched`, `detail`
distinguishing the two by `reason=`) and a separate counter
(`yuzu_scim_saml_link_unmatched_total` /
`yuzu_scim_saml_link_ambiguous_total` — kept separate because an ambiguous
`externalId` is a more actionable misconfiguration than ordinary drift);
`lookup_store_error` drives `auth.saml.link_lookup_failed` and
`yuzu_scim_saml_link_lookup_failures_total`, distinct from the two above
so a store outage is never misread as "no matching SCIM user."

At deprovision time, `maybe_flag_saml_d2_unlinked` (the direct SAML
analogue of D2's `maybe_flag_d2_unlinked`) fires
`yuzu_scim_deprovision_saml_unlinked_total` when a deprovisioned
resource's `externalId` has zero rows in `saml_identity_links`
(`ScimStore::saml_links_for_scim_id`, queried **specifically** — never
OIDC's `links_for_scim_id`, and never a `principals.size()` proxy, the
same C2-derived discipline item 6 above already applies to the ordinary
SAML revoke pass) but a `saml_login_observations` row shows a NameID
matching that `externalId`.

**The honest split — why this is two detectors, not one, and what neither
one covers.** Login-time and deprovision-time catch genuinely different
SAML failure shapes, not the same shape observed twice:

- *Login-time* (`link_unmatched`/`link_lookup_failed`) fires for a
  **stable-Format** NameID whose active-`externalId` lookup actually ran
  and returned zero/ambiguous/error — because a stable-Format login always
  reaches that lookup as part of ordinary link formation.
- *Deprovision-time* (`maybe_flag_saml_d2_unlinked`) fires for an
  **unstable-Format** NameID whose *value* matches — a login that never
  reached the lookup at all (the Format gate short-circuited it), so only
  the observation record, checked later, can surface the match.
- **Neither one attributes a stable-Format NameID that never matches any
  `externalId`, if that fact is only discovered at deprovision time.**
  OIDC's D2 can re-check a *second* candidate claim (`oid`) against the
  deprovisioned resource after the fact; SAML has no second candidate to
  fall back to, so re-checking at deprovision time would mean guessing,
  not detecting. This case is caught at **login time instead**
  (`link_unmatched`'s `no_active_match` branch fires the moment the
  mismatch is observable) — the detector is not blind to it, it simply
  fires at a different point in the lifecycle than the OIDC reader might
  expect. True **deprovision-time** attribution of a pure stable-Format
  drift case — i.e., proving from deprovision-time evidence alone, without
  relying on having caught the earlier login, that a given deprovisioned
  slug's `externalId` was a SAML drift case — is deferred to **issue
  #3098** (a second SAML join attribute, or an operator-configured
  mapping, is the design space item #3098 opens; #3072 deliberately does
  not attempt it, to avoid fabricating CC6.8 evidence from a
  single-candidate join key).

**Two further residuals, stated honestly (governance hardening round,
UP-2/UP-3):**

- **UP-2 (fail-open observation write).** `record_saml_login_observation`'s
  write is called unconditionally but is itself fail-open, matching every
  other write on this login path: if the `ScimStore` write fails (a store
  blip during the login window), the login proceeds anyway and that
  specific login is simply never recorded — so a later deprovision's D2
  tripwire cannot fire for it, the identical shape as a missed
  `identity_links`/`saml_identity_links` write. This is **not** a security
  regression relative to pre-#3072: before this change there was no signal
  for this population at all, and D2 is a detective control, not a
  preventive one — deprovision-time revocation itself (§3/PR4a) is
  unaffected by an observation-write failure. The only externally visible
  effect is a blind spot in detection coverage, and it is itself surfaced:
  both the observation write and the link write share
  `yuzu_scim_saml_link_write_failures_total` (`bump_link_write_failure`,
  `saml_scim_link.cpp`), so a sustained non-zero rate on that counter is
  the honest signal that D2 coverage — not just linkage — is degraded for
  logins in that window.
- **UP-3 (no-GC + entity/format-agnostic match).** `saml_login_observations`
  rows are never pruned — a deliberate choice, not an oversight, following
  the same reasoning `oidc_login_observations` already applies and the
  routed clock-guarded-retention rule's "decide deliberately and record
  why": the table is a bounded upsert keyed on distinct
  `(entity_id, name_id, name_id_format)` identities (one row per identity
  ever observed, not one row per login event), and it exists to be durable
  CC6.8 evidence, not regenerable scratch data — `ResultSetStore`'s
  reasoning for pruning does not transfer here any more than it transfers
  to `oidc_login_observations`. Separately, `ScimStore::
  saml_observation_matches` matches on the `name_id` **value alone** —
  `WHERE name_id = $1`, with no `entity_id` or `name_id_format` predicate.
  This is safe under the single-pinned-IdP precondition already stated
  above (constraint 5 / item 6): with exactly one trusted `entity_id` in
  play, a name_id-value match cannot cross an IdP boundary. It is also,
  necessarily, **format-agnostic** — a consequence worth being explicit
  about: `maybe_flag_saml_d2_unlinked` therefore fires on *any* recorded
  NameID-value match for the deprovisioned resource's `externalId`,
  regardless of the Format under which it was observed, which makes it
  slightly **broader** than "catches the unstable-Format-but-value-matches
  case" alone (the framing used above and in `docs/auth-architecture.md`)
  — it would, for instance, also catch a stable-Format value-match whose
  *link write itself* failed (UP-2/`link_write_error`), a case the
  login-time signals do not separately name. This is an under-statement in
  the existing framing, not a false guarantee: the tripwire is strictly
  more protective than described, never less. A future multi-IdP OIDC-side
  change already requires partitioning by issuer per constraint 5's forward
  caveat; an eventual multi-`entity_id` SAML change would need the same
  discipline applied to `saml_observation_matches` before this
  format-agnostic match stays safe under more than one pinned IdP.
  `yuzu_scim_deprovision_saml_unlinked_total` remains a **review** signal
  for a human to investigate, not a hard alarm with a single root cause.

Full description (table schema, all four call sites, the audit-verb detail
shapes, the metric descriptions): `docs/auth-architecture.md` "SAML D2
observability (#3072)".

## Review provenance
Rev 2 folds: architect B1 (`oid` unbuilt) + B2 (overload infeasible) + lease-nesting/reorder/resolver/index/helper notes; security-guardian F1 (D1), F2 (D2), F3 (single-issuer precondition, constraint 5), F4 (`oid`, constraint 3), F5 (constraint 4 wording), F6 (60s residual), F7 (generic deny redirect). Both reviews called the core reconciliation idea sound; the defects were in the provenance interaction and the fail-loud realizability, now surfaced as D1/D2.

The SAML addendum (PR4a, 2026-08-13) folds one architect (codex-sol) BLOCK
from its plan review: the NameID-Format gate above (item 3) — an earlier
draft of the plan treated any NameID as a safe join key, which the BLOCK
correctly identified as unsafe for `transient` NameIDs.

PR4b (2026-08-13) closed the addendum's item 7 residual by porting §4's
deny-at-login backstop to SAML unchanged in shape (item 8 above) — no new
review findings against the design beyond the ones §4/PR3 already resolved
for OIDC; the LEFT-join/fail-closed/orphan-reprovision invariants carried
over directly.

#3072 (2026-08-14, item 9 above) closes the observability gap the addendum
had, until then, correctly argued was a non-gap given SAML's
single-candidate join key — the argument was sound for a claim-selection
detector, but did not account for a value-observation detector, which
needs no candidate selection to be worth building. Governance review
confirmed the C2-derived `saml_links_for_scim_id`-specificity discipline
(item 6 above) is correctly re-applied in `maybe_flag_saml_d2_unlinked`,
and that the #3098 deferral is stated honestly rather than silently
absorbed into #3072's scope.
