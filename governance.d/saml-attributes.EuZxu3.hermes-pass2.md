Warning: Unknown toolsets: google_meet, messaging
Adversarial Security Review Pass 2 — SAML display-name/email attributes
Branch: feat/auth-saml-attributes | Reviewer: Hermes (kimi-k2.6)

---

### Executive Summary

No Critical, High, or Medium findings. Three LOW observations: one Unicode-whitespace blanking in derivation, one C1-control preservation in sanitisation, and one unbounded linear scan when a configured attribute is absent. Backward-compatibility and Windows fail-closed behaviour are both confirmed safe.

---

### 1. DERIVATION CORRECTNESS

**Finding 1.1 — LOW**
- **File:Line:** `server/core/src/saml_provider.cpp:395-403` (`get_text`)
- **Scenario:** `get_text` trims only ASCII whitespace (`" \t\r\n"`). A malicious IdP can send an AttributeValue consisting entirely of Unicode whitespace (e.g., U+00A0 NO-BREAK SPACE, U+2003 EM SPACE). These survive `get_text`, survive `sanitize_attribute_value` (which strips only C0 controls + DEL), and pass the `!text.empty()` gate in `extract_first_attribute_value`. The resulting `Session::display_name` is invisible/blank in the dashboard nav-bar, `/whoami` JSON, and operator logs. This does **not** affect authz (stable `username`/`saml_principal` is untouched) or audit attribution (audit rows key on `saml_principal`, not `display_name`), but it misleads operator-facing UI and complicates manual log review.
- **Fix:** Extend the post-sanitisation emptiness check in `extract_first_attribute_value` (or `get_text`) to reject strings that contain no visible graphemes (e.g., by stripping Unicode whitespace categories and re-checking `empty()`).

**Finding 1.2 — LOW**
- **File:Line:** `server/core/src/saml_provider.cpp:498-499` (`sanitize_attribute_value`)
- **Scenario:** The sanitizer strips C0 controls (`< 0x20`) and DEL (`0x7F`) but preserves C1 controls (`0x80-0x9F`). A compromised IdP can inject C1 bytes such as U+0085 NEXT LINE (NEL) into the display-name or email attribute. These survive to `spdlog::info` at `auth.cpp:1158` and to `/whoami` JSON. Downstream log processors that interpret C1 controls may split log lines, producing the same class of multi-line log injection that the C0 stripping was designed to prevent (Gate 4 UP-1/2). This is the C1 sibling of Pass 1's Unicode line-separator observation.
- **Fix:** Extend `sanitize_attribute_value` to strip the full C1 control range: `0x80 <= c && c <= 0x9F`.

---

### 2. BACKWARD-COMPATIBILITY / FAIL-OPEN — VERIFIED SAFE

- **File:Line:** `server/core/src/saml_provider.cpp:524`, `auth.cpp:1143-1145`
- **Confirmation:** When both `--saml-name-attribute` and `--saml-email-attribute` are unset (default empty strings), `extract_first_attribute_value` returns empty immediately. `create_saml_session` falls through to `name_id` for `resolved_display`. This is byte-identical to the pre-change behaviour.
- **Coercion resistance:** The attribute names are loaded from `cfg_` at server boot (`server.cpp:3476-3477`). The IdP assertion never influences which attribute names are searched. No code path enables attribute parsing when the flags are unset.

---

### 3. RESOURCE / DoS

**Finding 3.1 — LOW**
- **File:Line:** `server/core/src/saml_provider.cpp:522-559` (`extract_first_attribute_value`)
- **Scenario:** The function stops at the first match, which is O(1) for the value-collection aspect. However, when the configured attribute is **absent** from the assertion, it walks **all** `AttributeStatement` nodes and **all** their `Attribute` children without a cap. A 1 MiB assertion (the upstream size limit, line 841) can contain tens of thousands of attribute nodes, forcing a linear scan on every login. `extract_group_values` has an explicit `kMaxGroupValues = 200` cap; the scalar attribute extraction has no equivalent scan budget.
- **Impact:** Bounded by the 1 MiB document size and only reachable on the SAML login path (not per-request), so the practical DoS window is narrow. Still, parity with the group-value cap is missing.
- **Fix:** Add an `kMaxAttributeScan` cap (e.g., 1000 `AttributeStatement` or `Attribute` nodes) and break early, returning empty if exceeded.

**Verified safe:**
- `sanitize_attribute_value` clamps to 256 bytes and the UTF-8 boundary walk is bounded by at most 3 back-steps (max sequence length 4).
- No unbounded allocation or quadratic walk.

---

### 4. WINDOWS/PLATFORM — VERIFIED SAFE

- **File:Line:** `server/core/src/server.cpp:3346-3352`
- **Confirmation:** The `_WIN32` unsupported-feature detector now enumerates `cfg_.saml_name_attribute.empty()` and `cfg_.saml_email_attribute.empty()` in the OR-chain. If either new flag is set on Windows, `spdlog::error` fires and `saml_provider_` stays null. The SAML routes gate on `is_enabled()`, which is always `false` on Windows (`saml_provider.cpp:27`). This is fail-closed with a loud ERROR log — never silently half-enabled.

---

### Audit / Authz Impact Assessment

- **Authz:** `Session::display_name` is never consulted by `check_permission`, `require_admin`, `effective_role`, RBAC reconcile, or any gate. Safe.
- **Audit:** Audit rows key on `session->username` (`saml_principal`). The audit detail string at `auth_routes.cpp:3905-3909` carries `name_id` and `admin_group`, not `display_name` or `email`. Safe from display-name spoofing in audit attribution.

---

### Severity Table

| # | Severity | File:Line | Scenario | Fix |
|---|----------|-----------|----------|-----|
| 1.1 | LOW | `saml_provider.cpp:395-403` | Unicode whitespace survives trimming → blank display_name | Reject strings with no visible graphemes after sanitisation |
| 1.2 | LOW | `saml_provider.cpp:498-499` | C1 controls (e.g., U+0085 NEL) survive sanitisation | Extend sanitizer to strip `0x80-0x9F` |
| 3.1 | LOW | `saml_provider.cpp:522-559` | Unbounded scan of AttributeStatement/Attribute nodes when attribute absent | Add `kMaxAttributeScan` cap for parity with group-value cap |

**No findings at Critical, High, or Medium severity.**
