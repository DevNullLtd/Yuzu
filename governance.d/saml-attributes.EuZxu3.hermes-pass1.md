Warning: Unknown toolsets: google_mee**ADVERARIAL SECURITY REVIEW — PASS 1 of 2**
**Branch:** `feat/auth-saml-attributes`  
**Scope:** SAML display-name + email attribute parsing (session enrichment only)  
**Reviewer:** adversarial-first, trace real call paths

---

## EXECUTIVE SUMMARY

No **Critical** or **High** findings. All three load-bearing invariants hold under adversarial analysis. One **LOW** observation on sanitizer scope (C1/Unicode line-separator survivorship) — documented for pass-2 completeness but arguably by design.

---

## INVARIANT 1: XSW BINDING — EXTRACTOR WALKS ONLY FROM THE VERIFIED `assertion` NODE

**VERDICT: HOLDS**

### Evidence traced

1. `saml_provider.cpp:validate_response` enforces exactly-one Assertion at lines 917–922:
   ```cpp
   if (assertions.size() > 1) {
       return std::unexpected("XSW rejected: response contains " + ...);
   }
   xmlNodePtr assertion = assertions[0];
   ```
   Any injected second assertion causes hard rejection **before** `extract_first_attribute_value` is reached.

2. The XSW binding at lines 1104–1150 further hardens: `xmlAddID` duplicate-ID rejection, `ref_id != assertion_id` rejection, and `has_duplicate_id(root, assertion, ...)` decoy scan. Only after all three layers pass does control reach the attribute extractors.

3. `extract_first_attribute_value` (`saml_provider.cpp:522–559`) takes `xmlNodePtr assertion` as its first parameter and walks **only** `xmlFirstElementChild(assertion)` / `xmlNextElementSibling(...)`. It never touches `root` or `doc`.

4. Namespace checks are **byte-identical** to `extract_group_values` at every level:
   - `AttributeStatement`: `stmt->ns->href` must equal `kSamlAssertionNs` (line 530)
   - `Attribute`: `attr->ns->href` must equal `kSamlAssertionNs` (line 537)
   - `AttributeValue`: `val->ns->href` must equal `kSamlAssertionNs` (line 545)

5. The `get_attr(attr, "Name") != attr_name` check (line 540) is exact string equality. There is no wildcard, prefix, or namespace-qualified matching that could drift onto a differently-namespaced attribute.

### Attack scenario attempted
An XSW variant nests a forged `<saml:AttributeStatement>` inside a second, unsigned assertion. The `collect_assertions` → `assertions.size() > 1` gate rejects at line 918–921 **before** the extractor runs. Even if an attacker could somehow make `collect_assertions` return only the signed assertion (e.g., by hiding the second assertion in a non-SAML namespace), the `has_duplicate_id` scan (line 1144) registers the signed assertion's ID first; any decoy sharing that ID is rejected. The extractor is unreachable.

---

## INVARIANT 2: SESSION-ENRICHMENT ONLY — `display_name` / `email` NEVER INFLUENCE IDENTITY, AUTHZ, ADMIN ROLE, OR SCIM LINKAGE

**VERDICT: HOLDS**

### Call-path audit

| Decision | Input used | `display_name` / `email` involved? |
|---|---|---|
| **Stable principal (identity)** | `saml::saml_principal_id(entity_id, name_id)` | **NO** — computed from `name_id` only |
| **Admin role** | `resolve_role_from_groups(groups, admin_group)` | **NO** — derived from `groups` vector only |
| **Session minting** | `AuthManager::create_saml_session(...)` | `saml_display_name` → `Session::display_name` only; `saml_email` → log line + fallback only |
| **RBAC reconcile** | `rbac_store_->reconcile_idp_memberships(saml_principal, "saml", asserted)` | **NO** — uses `groups`, not display/email |
| **SCIM linkage** | `saml::link_saml_login_to_scim(scim_store_, saml_entity_id, saml_name_id, ...)` | **NO** — linkage uses `saml_name_id` only |
| **Deprovision backstop** | `saml::saml_login_denied_deprovisioned(scim_store_, saml_entity_id, saml_name_id)` | **NO** — keys on `name_id` only |
| **Audit principal** | `audit_log_for_principal(req, ..., saml_principal, ...)` | **NO** — audit principal is `saml_principal` (stable principal) |
| **Audit detail** | `"auth_source=saml;name_id=" + sanitize_detail_value(saml_name_id)` | **NO** — `display_name`/`email` deliberately omitted from audit detail |

### Session field readers checked

`Session::display_name` is read in:
- **UI rendering** (`/api/me` endpoint → `dashboard_ui.cpp`, `help_ui.cpp`, etc.) via `fetch('/api/me')` → `d.display_name || d.username` rendered into `textContent`. No authz logic.
- **No authorization gate reads it.** Searched all call sites of `require_auth`, `require_admin`, `require_permission`, `require_scoped_permission`, `require_list_read`, `effective_role`, `is_elevated`, `synthesize_token_session`, `revalidate_stream`, `engine_credential_state`. Every gate keys on `session->username`, `session->role`, `session->token_scope_service`, `session->mcp_tier`, `session->principal_kind`, or `session->elevated_until`. **Zero reads of `display_name`.**

### Attack scenario attempted
A compromised IdP asserts `display_name="admin"` or `email="admin@corp.com"` hoping to influence role assignment or SCIM linkage. The admin role is resolved **exclusively** from `groups` via `resolve_role_from_groups` (`auth.cpp:1018–1035`). The SCIM link is formed from `saml_name_id` only. The display/email values are dead data for UI rendering.

---

## INVARIANT 3: `sanitize_attribute_value()` — ATTEMPTED DEFEAT ANALYSIS

**VERDICT: NOT DEFEATED ON STATED SCOPE.** No Critical/High. One LOW observation on scope boundary.

### Code under test
```cpp
// saml_provider.cpp:498–508
static std::string sanitize_attribute_value(std::string s) {
    std::erase_if(s, [](unsigned char c) { return c < 0x20 || c == 0x7F; });
    if (s.size() > kMaxAttributeValueLen) {
        std::size_t cut = kMaxAttributeValueLen;
        while (cut > 0 && (static_cast<unsigned char>(s[cut]) & 0xC0) == 0x80) --cut;
        s.resize(cut);
    }
    return s;
}
```

### Attempt 1: Multi-byte truncation producing invalid UTF-8

**Result: FAILED TO DEFEAT.** The clamp logic is correct for valid UTF-8 input.

- The loop checks `s[cut]` (the first byte that would be *removed*) and decrements `cut` while it's a continuation byte (`0b10xxxxxx`).
- When the loop stops, `s[cut]` is either an ASCII byte or a lead byte. `resize(cut)` keeps bytes `0..cut-1`, which ends exactly at the last complete codepoint.
- Exhaustive boundary cases checked (2-byte, 3-byte, 4-byte sequences crossing the 256-byte boundary). No valid UTF-8 input produces invalid UTF-8 output.

### Attempt 2: Over-long value

**Result: FAILED TO DEFEAT.** The clamp is hard at `kMaxAttributeValueLen = 256` bytes. `get_text` trims whitespace first, then the sanitizer clamps. The resulting string is never longer than 256 bytes.

### Attempt 3: Embedded newline/CR surviving into the spdlog line

**Result: FAILED TO DEFEAT for C0 controls.** `\n` (0x0A), `\r` (0x0D), and `\t` (0x09) are all `< 0x20` and are stripped by `std::erase_if`. Numeric character references (`&#x0A;`, `&#x0D;`) are expanded by libxml2 during parsing, so the actual bytes `< 0x20` reach the sanitizer and are removed.

**However:** Unicode line-separator characters **outside** the C0 block survive because their individual UTF-8 bytes are `>= 0x20` and `!= 0x7F`:
- **U+0085 NEL** (UTF-8: `0xC2 0x85`) — C1 control, "Next Line"
- **U+2028 Line Separator** (UTF-8: `0xE2 0x80 0xA8`)
- **U+2029 Paragraph Separator** (UTF-8: `0xE2 0x80 0xA9`)

These could split a log line in Unicode-aware terminals/viewers. The sanitizer's documented scope is "C0 controls + DEL" — this is consistent with `detail::sanitize_detail_value` in `auth_routes.cpp` which has the same limitation. Rating this **LOW** (by-design scope boundary, not a bypass of the stated contract).

### Attempt 4: Value that still splits a log line

**Result: NOT DEFEATED beyond LOW observation above.** The C0 newline/CR/tab are stripped. Unicode line separators survive but are outside the sanitizer's stated scope. No additional attack vector found.

---

## LOW OBSERVATION (no fix required, pass-2 note)

**File:** `server/core/src/saml_provider.cpp:498`  
**Scope:** Sanitizer completeness  

The sanitizer strips C0 controls (`0x00–0x1F`) and DEL (`0x7F`). C1 controls such as **U+0085 NEL** and format characters such as **U+2028 / U+2029** (Unicode line separators) survive. In a Unicode-aware log viewer these can still effect a line break. If the project wants a stronger "no log splitting" guarantee, extending the erasure predicate to cover `0x85` and the `U+2028`/`U+2029` byte patterns would close the gap. This is a **LOW** because the sanitizer's explicit contract is C0+DEL, and the same gap exists in `detail::sanitize_detail_value`.

---

## CONCLUSION

| Invariant | Status | Severity |
|---|---|---|
| 1. XSW-verified assertion binding for new attributes | **HOLDS** | — |
| 2. Session-enrichment only (no authz/identity/SCIM influence) | **HOLDS** | — |
| 3. sanitize_attribute_value defeat attempts | **NOT DEFEATED** | — |
| C1/Unicode line separator survivorship | By-design scope boundary | **LOW** |

**Critical findings: 0**  
**High findings: 0**  
**Medium findings: 0**  
**Low findings: 1** (sanitizer scope boundary — C1 / Unicode line separators)
