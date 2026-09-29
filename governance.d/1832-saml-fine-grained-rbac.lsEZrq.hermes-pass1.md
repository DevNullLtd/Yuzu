Warning: Unknown toolsets: messaging
I've completed a thorough adversarial review of the SAML fine-grained RBAC change (commit `95bc2b52`). After tracing every code path through `auth_routes.cpp:3144-3238`, `saml_provider.hpp:kMaxGroupValues`, `rbac_store.cpp:reconcile_idp_memberships`, and the surrounding ACS handler flow, I found **no exploitable vulnerabilities** at Critical or High severity. The design is fail-closed where it matters, namespacing is correct, and ordering is safe.

Below are my findings with severity, file:line, concrete exploit scenario (where applicable), and fix recommendation.

---

## Summary Table

| Finding | Severity | File:Line | Status |
|---------|----------|-----------|--------|
| 1. No `groups_claim_reconcilable` equivalent for SAML — deprovision gap for "all groups removed" cases | Medium | `auth_routes.cpp:3146` | Documented limitation; gap exists but not exploitable for elevation |
| 2. Route-level test gap: truncation→deny branch untested at ACS level | Medium | `test_saml_routes.cpp:2177` | No runtime exploit; coverage gap only |
| 3. `is_blank()` redundancy + potential cap-slot waste from XML whitespace | Low | `saml_provider.cpp:470-471`, `rbac_store.cpp:2380` | Harmless; minor hardening opportunity |
| 4. Post-mint `group_cap_truncated` counter reachable with stale truncated data after exception | Low | `auth_routes.cpp:3373` | Defensive; unlikely in practice |

---

## Finding 1 — SAML Cannot Distinguish "Attribute Absent" from "Attribute Present but Empty" (MEDIUM)

**File:** `server/core/src/auth_routes.cpp:3146`  
**Class:** DEPROVISION GAP

**What it is:** OIDC has `groups_claim_reconcilable(claims)` (`oidc_provider.hpp:110`) which explicitly distinguishes three states: claim absent, claim overaged, and claim present+readable. SAML has no equivalent signal. The verifier's `extract_group_values` returns an empty `groups` vector in BOTH of these cases:
- The configured `group_attribute` is entirely absent from the assertion
- The attribute is present but contains only empty/whitespace `<AttributeValue>` nodes

Both hit the `asserted_groups.empty()` branch and **SKIP** reconcile, leaving existing `saml:` memberships untouched.

**Concrete scenario:** A legitimate user is a member of `saml:eng` and `saml:sales` via prior logins. Their IdP administrator removes them from ALL IdP groups. The IdP now sends an assertion where the group attribute is still present but carries zero meaningful values. The ACS handler SKIPS reconcile (because `groups` is empty), so the user's `saml:eng` and `saml:sales` memberships persist indefinitely. If this user was also granted admin via fine-grained RBAC on one of those groups, they retain admin.

**Why this is MEDIUM not Critical/High:** The commit explicitly documents this as a known limitation. The SCIM deprovision chokepoint (PR4b) remains the supported full-deprovision path. The IdP cannot exploit this to **gain** new roles — it can only **retain** existing ones after a legitimate removal. There is no assertion-only elevation.

**Fix:** Add a `saml_groups_reconcilable`-style gate to `SamlAssertion` (e.g., a new `bool group_attribute_present` field set by `extract_group_values` when the attribute node is found, regardless of value count). If the attribute IS present but values are empty, reconcile-to-zero is safe. If the attribute is ABSENT, skip. This would close the gap for IdPs that keep the attribute present with empty values when a user has no groups.

---

## Finding 2 — Route-Level Test Gap for Truncation→Deny Branch (MEDIUM)

**File:** `tests/unit/server/test_saml_routes.cpp:2177-2187`  
**Class:** TEST / VERIFICATION GAP

**What it is:** The commit correctly raises `kMaxGroupValues` from 64→200 and adds fail-closed truncation→deny logic in `auth_routes.cpp:3157-3187`. However, the corresponding route-level test is a documented `SKIP` because httplib's 8 KiB form-urlencoded cap makes a >200-value assertion unreachable via HTTP-POST.

The commit comment (line 2158-2176) explicitly admits:
> "The DENY LOGIC itself [...] is a straightforward, size-independent consumer of `SamlAssertion::group_cap_truncated` [...] The sibling 'reconcile store error' test below covers the same general DENY SHAPE [...] but it is a DIFFERENT branch reached via a DIFFERENT cause [...] It does NOT exercise this branch's specific `reason=group_count_exceeded` audit detail, nor does it touch `yuzu_saml_group_cap_truncated_total` at all — neither is directly asserted by any test in this file today."

**Concrete scenario:** A future refactor (e.g., moving the metric bump, reordering the deny logic, or changing the redirect URL) could break the truncation→deny path without any test catching it. While `test_saml_provider.cpp` covers the **parser-level** truncation mechanic, no automated test covers the **route-level** deny shape (audit rows, metrics, cookie clearing, redirect URL).

**Fix:** Add a direct unit test of `AuthRoutes`'s `/saml/acs` handler logic that injects a `SamlAssertion` with `group_cap_truncated=true` and asserts:
1. `res.status == 302` to `/login?error=saml`
2. `auth.saml_login_failed` audit row with `reason=group_count_exceeded`
3. `yuzu_saml_group_cap_truncated_total` counter == 1
4. No session cookie in response

This requires bypassing the HTTP layer and calling the handler directly, or adding a synthetic injection point to the test fixture.

---

## Finding 3 — XML-Trimmed Whitespace Values Waste Cap Slots Before `is_blank` Filter (LOW)

**File:** `server/core/src/saml_provider.cpp:470-471`, `server/core/src/rbac_store.cpp:2380`  
**Class:** MINOR HARDENING GAP

**What it is:** `get_text()` trims ` \t\r\n` (line 400-403). Empty post-trim values are skipped in `extract_group_values` (line 471). But `is_blank()` in `reconcile_idp_memberships` checks ALL whitespace characters via `std::isspace()` (line 181). If an IdP asserts a group value containing only `\v` (vertical tab) or `\f` (form feed), `get_text()` would preserve it (not trimmed), and it would reach `reconcile_idp_memberships` as a non-empty string. `is_blank()` would then skip it.

**Impact:** Such a value consumes one slot in the 200-value `kMaxGroupValues` cap in `extract_group_values`, but is then dropped in `reconcile_idp_memberships`. An attacker with control of the IdP (or a compromised IdP) could waste up to 200 cap slots with whitespace-only values, reducing the effective group count for legitimate values.

**Concrete exploit:** A malicious IdP sends an assertion with 200 `<AttributeValue>` nodes containing `\v\v\v` followed by legitimate group values. The verifier collects 200 values (all whitespace-only), sets `group_cap_truncated = false` (because no 201st value was reached). `reconcile_idp_memberships` skips all 200 as blank. The user's legitimate groups are never reconciled. The login succeeds with zero groups. The user retains their old `saml:` memberships (from prior logins) because the empty-skip branch is taken.

**Why this is LOW:** This requires IdP compromise. The user doesn't gain new privileges — they simply don't get updated group mappings for THIS login. Their old mappings persist. This is more of a DoS/availability issue than a privilege escalation.

**Fix:** Move the `is_blank` equivalent check (or a broader whitespace trim) into `extract_group_values` in `saml_provider.cpp`, so whitespace-only values are skipped BEFORE counting against `kMaxGroupValues`. This also eliminates the redundant `is_blank` check in `reconcile_idp_memberships` for SAML-sourced values (it remains useful for OIDC).

```cpp
// In saml_provider.cpp extract_group_values, after get_text():
std::string text = get_text(val);
if (text.empty()) continue;
// ADD: skip whitespace-only values before cap counting
auto first_non_ws = text.find_first_not_of(" \t\r\n\v\f");
if (first_non_ws == std::string::npos) continue;
```

---

## Finding 4 — Post-Mint `group_cap_truncated` Counter Could Fire After Exception Interruption (LOW)

**File:** `server/core/src/auth_routes.cpp:3373-3376`  
**Class:** DEFENSIVE / RESILIENCE

**What it is:** The `group_cap_truncated` counter is bumped in TWO places:
1. Line 3179: inside the reconcile block's truncation→deny branch (active reconcile path)
2. Line 3373: in the post-session cleanup block (non-reconcile or legacy path)

The post-session block is inside the `try { ... } catch (...) { ... }` block (lines 3009-3377). If an exception were thrown AFTER `create_saml_session` (line 3297) but BEFORE the post-mint check (line 3315), the `catch` at line 3378 would handle it. But the post-session `group_cap_truncated` check at 3373 is BEFORE the catch. So if an exception occurs between session mint and line 3373, the counter would not fire.

More importantly: the post-mint block at 3373 checks `result.value().group_cap_truncated` without re-checking `rbac_store_` or `cfg_.saml_group_attribute`. The comment at 3361-3372 correctly explains that this code is reached ONLY when the reconcile block did NOT already deny. But if a future refactor accidentally moves this code or changes the outer `if` conditions, this could double-count.

**Concrete scenario:** None today. This is a code-maintenance risk, not a live exploit.

**Fix:** Add an explicit guard comment or assertion that `group_cap_truncated` is false when the reconcile block was active:
```cpp
// Defensive: if we reached here with group_cap_truncated=true, the reconcile
// block above MUST have been skipped (rbac_store_ absent or group_attribute
// unconfigured). Under an active reconcile, truncation is a hard deny above.
if (result.value().group_cap_truncated) {
    // This path is ONLY for legacy non-reconcile deployments.
    ...
}
```

---

## What Was Checked and Found Safe

| Concern | Finding |
|---------|---------|
| **Privilege Escalation (assertion alone elevates)** | **NO EXPLOIT.** The assertion only creates `saml:<value>` group memberships. Role assignments are operator-authored via `/rbac/roles`. The coarse `--saml-admin-group` is a separate, intentional mechanism. |
| **False-Deprovision (truncated set reaches reconcile)** | **NO EXPLOIT.** `group_cap_truncated`→`return` at line 3185-3187 is fail-closed. The `return` exits before `reconcile_idp_memberships` is called. |
| **Namespace/Confused-Deputy** | **NO EXPLOIT.** `namespaced_group_name("saml", gid)` → `"saml:" + gid`. Cannot forge `entra:`, `local:`, or `engine:` groups. `sec-L1` source-mismatch guard in `reconcile_idp_memberships` (line 2442-2450) blocks joining a differently-sourced pre-existing row. |
| **Fail-Open (reconcile error proceeds to mint)** | **NO EXPLOIT.** `if (!reconciled) { ... return; }` at lines 3196-3219 is unambiguous fail-closed with immediate handler return. |
| **Deprovision Gap (empty→skip retains roles)** | **Documented design limitation, not an exploit.** SCIM is the full-deprovision path. The IdP cannot exploit empty-skip to gain roles, only to retain old ones after legitimate removal. |
| **Injection (`:` or path chars in group values)** | **NO EXPLOIT.** `sanitize_pg_text` scrubs NUL bytes; libpq parameterized queries prevent SQL injection. Namespacing prevents principal forgery. Values are treated as opaque strings. |
| **Ordering (reconcile before deprovision-deny, or partial write)** | **NO EXPLOIT.** Reconcile runs AFTER PR4b primary deny (~3069-3118) and BEFORE link formation + session mint. A reconcile deny returns before any side effects. |

---

## Bottom Line

The SAML fine-grained RBAC commit is **well-hardened**. The fail-closed truncation→deny is correct, namespacing prevents confused-deputy, and reconcile errors abort before session mint. The governance pipeline's 10 agents likely caught the serious issues during earlier iterations (the fall-through revert in `rbac_store.cpp`, the `sec-L1` source check, the reserved-prefix guard).

The only actionable security-relevant finding is **Finding 1** (the absence of a `groups_claim_reconcilable` equivalent for SAML), which is a MEDIUM-severity deprovision gap — known, documented, and bounded by SCIM being the authoritative deprovision path. The other findings are test gaps and minor hardening opportunities.
session_id: 20260815_230930_16ec10

