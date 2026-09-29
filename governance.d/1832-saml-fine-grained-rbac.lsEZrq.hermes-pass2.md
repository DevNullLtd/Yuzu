Warning: Unknown toolsets: messaging
After a thorough adversarial review of commit `95bc2b52` across `auth_routes.cpp`, `saml_provider.hpp/cpp`, `rbac_store.cpp`, `auth.cpp`, and the test surface, I find **nothing exploitable**. The design is fail-closed at every boundary I could reach. Below is the explicit confirmation per concern you listed, with file:line references.

---

### PASS 1: Seven checked concerns

#### 1. PRIVILEGE ESCALATION — Can a malicious/compromised IdP grant a role beyond operator-authored grants?

**Finding: None. Checked and ruled out.**

- **Assertion ALONE cannot elevate.** `reconcile_idp_memberships` (rbac_store.cpp:2359) creates/upserts `saml:<value>` **group principals**, not roles. A role is only effective if an operator has previously authored a `principal_roles` row mapping that `saml:<value>` group to a role via the management-group API. The IdP assertion cannot create, modify, or bypass `principal_roles` rows.
- **No confusion between coarse and fine-grained.** The coarse `--saml-admin-group` (auth_routes.cpp:3003) is evaluated in `resolve_role_from_groups` (auth.cpp:1018), which sets `Session.role = admin` as a session-level property. Fine-grained grants flow through `collect_roles` → `check_permission` (rbac_store.cpp:2507, 2536). These are orthogonal mechanisms: `require_admin` gates on the session role, `require_permission` gates on RBAC roles. A malicious IdP cannot coerce the fine-grained path into granting the admin session role, nor can it bypass operator-authored grants.

#### 2. FALSE-DEPROVISION / DELETE-STALE — Is truncation=>deny actually closed?

**Finding: None. Checked and ruled out.**

- **Truncation triggers DENY before reconcile.** At auth_routes.cpp:3157, `group_cap_truncated == true` causes an immediate redirect-to-login with `Set-Cookie` cleared. The `return` at line 3187 guarantees `reconcile_idp_memberships` is never called.
- **kMaxGroupValues alignment.** `saml::kMaxGroupValues = 200` (saml_provider.hpp:50) matches `RbacStore::kMaxIdpGroupsPerLogin = 200` (rbac_store.hpp:324). The verifier stops at 200 values; the ACS handler denies at the same boundary. A truncated set never reaches the RBAC store.

#### 3. NAMESPACE / CONFUSED-DEPUTY — Can a SAML assertion place a user into an `entra:` or `local:` group?

**Finding: None. Checked and ruled out.**

- **Hardcoded source prefix.** `reconcile_idp_memberships` is called with literal source `"saml"` (auth_routes.cpp:3195). `namespaced_group_name` (rbac_store.cpp:892) computes `source + ":" + external_id`, producing `saml:<value>` unconditionally.
- **Source-verification on join.** Before adding a membership, reconcile queries the existing `groups` row and verifies `source == existing` (rbac_store.cpp:2442). If an operator pre-created a group `entra:admins` with source `entra`, a SAML reconcile for external_id `admins` computes `saml:admins`, which is a different DB row. No collision.
- **Reserved-prefix guard on local creation.** `create_group` rejects local groups with reserved prefixes (`entra:`, `saml:`, `ad:`, `engine:`) via `has_reserved_idp_prefix` (rbac_store.cpp:165, 2237). A local operator cannot create a colliding group.

#### 4. FAIL-OPEN — Any path where reconcile error, truncation, or store degradation proceeds to mint a session?

**Finding: None. Checked and ruled out.**

- **Reconcile error => deny.** At auth_routes.cpp:3196, `!reconciled` triggers redirect-to-login with cookie cleared (line 3217-3219).
- **Truncation => deny.** At auth_routes.cpp:3157, `group_cap_truncated` triggers redirect-to-login (line 3185-3187).
- **Store not open => deny.** `reconcile_idp_memberships` returns `unexpected("database not open")` (rbac_store.cpp:2395), which the ACS handler treats as `!reconciled` and denies.
- **Post-mint deprovision re-check.** Even after `create_saml_session` (line 3297), a concurrent SCIM deprovision triggers `invalidate_user_sessions` (line 3321) and denies before the cookie is set (line 3356).

#### 5. DEPROVISION GAP — Empty=>skip means removing a user from all IdP groups doesn't revoke `saml:` roles until SCIM acts

**Finding: Documented and accepted boundary. Not exploitable as coded.**

- The empty/absent skip is explicitly gated at auth_routes.cpp:3146: `if (asserted_groups.empty()) { ... skip ... }`. This is intentional because SAML cannot distinguish "attribute absent" from "present but zero values". The documented deprovisioning path is SCIM (PR4a/PR4b). The code comment at lines 3135-3143 explains this explicitly.
- This is **not** an authentication bypass: a deprovisioned user is still blocked by `saml_login_denied_deprovisioned` (line 3089) before reconcile is reached.

#### 6. INJECTION — Asserted group values flow into `saml:<value>` names. Any injection that escapes the namespace?

**Finding: None. Checked and ruled out.**

- **Colon injection in external_id is harmless.** `namespaced_group_name("saml", "foo:bar")` produces `"saml:foo:bar"`. This is a literal string stored in the DB. `collect_roles` matches `group_name` exactly; there is no parsing of sub-namespaces after storage. An asserted group `"entra:admins"` becomes `saml:entra:admins`, which is distinct from any `entra:` row.
- **SQL injection is prevented.** All values are passed through `sanitize_pg_text()` before SQL execution (rbac_store.cpp:2422, 2457, 2475).
- **Blank values are dropped.** `extract_group_values` skips empty/whitespace values (saml_provider.cpp:471). `reconcile_idp_memberships` drops blanks via `is_blank` (rbac_store.cpp:2380).

#### 7. ORDERING — Could reconcile run before deprovision-deny, or leave a partial write/session on a denied path?

**Finding: None. Checked and ruled out.**

- **Ordering is correct.** The sequence in the `try` block is:
  1. `validate_response` (3010)
  2. NameID namespace check (3031)
  3. `is_valid_saml_component` (3049)
  4. `saml_principal_id` construction (3067)
  5. **Primary deprovision deny** (3089) — `return` if denied
  6. **Reconcile** (3144) — only reached if primary deny passed
  7. Link formation (3256)
  8. `create_saml_session` (3297)
  9. Post-mint re-check (3315)
- **No partial session on deny.** Every deny branch (validation failure, namespace rejection, sanitation failure, deprovision deny, truncation deny, reconcile error) executes `res.set_header("Set-Cookie", kBindCookieClear)` and returns before `create_saml_session`.

---

### PASS 2 EXTRA LENS

#### (a) Coarse admin + fine-grained grant compounding

**Finding: No confused deputy, but the two privilege planes are orthogonal.**

- The coarse `--saml-admin-group` grants `Session.role = admin` (auth.cpp:1130). Fine-grained `saml:<value>` grants flow through `check_permission`/`collect_roles` (rbac_store.cpp:2507). 
- **No compounding elevation.** `require_admin` gates on session.role alone; it does not consult RBAC. `check_permission` gates on RBAC roles alone; it does not know about the session admin role. A user in the admin group who also holds fine-grained grants cannot gain more than the union of those two independent planes. There is no endpoint where a fine-grained grant amplifies the admin session role (or vice versa) in an unexpected way.

#### (b) Session-fixation / principal-identity stability

**Finding: Stable and non-forgeable.**

- `saml_principal_id(entity_id, name_id)` = `"saml:" + entity_id + "#" + name_id` (saml_principal.hpp:49).
- `entity_id` is operator-configured (`cfg_.saml_idp_entity_id`) and verified by the SAML provider against the signed `<saml:Issuer>` before the ACS handler sees it.
- `name_id` is extracted from the XSW-verified assertion node.
- Neither component is attacker-controllable. An attacker would need to forge a valid XML-DSig assertion (N1: pinned cert verification) to influence either value.

#### (c) Whitespace/blank-value cap-exhaustion elevation

**Finding: No elevation variant.**

- Empty/whitespace-only values are dropped in `extract_group_values` (saml_provider.cpp:471) AND in `reconcile_idp_memberships` (rbac_store.cpp:2380). They do not consume slots in the `groups` vector or the `asserted` list.
- An attacker cannot crowd out legitimate groups with blank values to prevent deprovisioning. Even if they could, the worst outcome is a truncated set being denied (fail-closed), not stale groups persisting.

#### (d) Reconcile running for a session that should have been denied by an earlier gate

**Finding: Not possible with current ordering.**

- Reconcile at line 3144 is reached only after `validate_response` success, namespace/sanitation checks pass, and the primary `saml_login_denied_deprovisioned` deny returns false.
- Replay protection (`InResponseTo` consumption), XSW checks, and condition validation all happen inside `validate_response` before the ACS handler proceeds.

---

### What I explicitly checked that was NOT exploitable

- Truncated group list reaching `create_saml_session` (denied at line 3157 before mint).
- `saml:` namespace injection via colons in asserted group values (produces literal `saml:foo:bar`, no collision).
- Concurrent deprovision race between reconcile and session mint (caught by post-mint re-check at line 3315, invalidated).
- Reconcile error leaving stale RBAC state without session (reconcile uses its own transaction; a retry login is idempotent).
- `rbac_store_ == nullptr` path skipping truncation check (only affects coarse admin matching; truncation can only deny admin, never grant it).

**Bottom line: every attack surface I could reach is bounded, fail-closed, and correctly ordered. No Critical/High/Medium findings. The feature is safe to ship.**
session_id: 20260815_231729_82a1d9

