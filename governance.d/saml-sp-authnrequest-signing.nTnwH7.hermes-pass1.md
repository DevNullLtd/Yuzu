Warning: Unknown toolsets: messaging

session_id: 20260814_193711_9c3b16
## Adversarial Security Review — SAML 2.0 SP AuthnRequest Signing

**Scope:** `feat/auth-saml-authnrequest-signing` (commits `155afcbc..HEAD`)  
**Reviewer:** Independent adversarial pass  
**Focus areas checked:** Signature-base correctness, crypto posture, key-at-rest hygiene, fail-closed/downgrade properties, endpoint abuse, and impact on existing SAML security controls (pinned-IdP-cert verify, XSW, InResponseTo replay, SCIM deprovision).

---

### Finding 1: Weak RSA key sizes accepted without floor — MEDIUM

**File:** `server/core/src/saml_provider.cpp:595-607`  
**What:** After parsing a successfully decrypted RSA key, the code never checks `EVP_PKEY_get_bits`, `RSA_size`, or `EVP_PKEY_bits`. A 512-bit or 1024-bit key (or any RSA key that OpenSSL will parse) is accepted silently. NIST SP 800-57 and current practice treat 1024-bit RSA as insufficient for production use; 512-bit is trivially factorable.

**Impact:** If an operator deploys a weak key, the IdP may accept the signature (depending on its own policy), but the SP is materially vulnerable to signature forgery via lattice/CDH attacks or commodity factorization. This is a configuration-induced cryptographic downgrade that the code could prevent at boot.

**Concrete check:** The test `test_saml_provider.cpp` generates a 2048-bit key, but the production constructor has no floor.

**Fix:** Reject keys below 2048 bits after the `EVP_PKEY_base_id` check:
```cpp
if (EVP_PKEY_get_bits(parsed.get()) < 2048) {
    signing_init_failed_ = true;
    signing_init_error_ = "SAML SP signing key must be at least 2048 bits";
    ...
}
```

---

### Finding 2: RSA-PSS keys are not fully rejected — implementation mismatches documented intent — LOW

**File:** `server/core/src/saml_provider.cpp:596`  
**What:** The code checks `EVP_PKEY_base_id(parsed.get()) != EVP_PKEY_RSA`. In OpenSSL, `EVP_PKEY_base_id` returns `EVP_PKEY_RSA` for **both** plain RSA keys and RSA-PSS keys (`EVP_PKEY_RSA_PSS` has base id `EVP_PKEY_RSA`). The inline comment explicitly says "Reject EC and RSA-PSS (and anything else) — only plain RSA (PKCS#1 v1.5) is supported," but the guard does not achieve this.

**Impact:** Depends on OpenSSL version and build:
- If OpenSSL refuses PKCS#1 v1.5 padding on an RSA-PSS key, `EVP_PKEY_CTX_set_rsa_padding` fails, `rsa_sha256_sign` returns `{}`, and `build_authn_request` fails closed (safe).
- If OpenSSL allows the operation, the SP signs with an RSA-PSS key using PKCS#1 v1.5 padding. This is mathematically sound but violates the documented "RSA only" contract. An IdP that inspects the key type (e.g., from SP metadata) may reject the assertion, causing interop failure. More importantly, if a future change relaxes the padding check or if an operator assumes "RSA-only" means "no PSS," this gap creates a latent algorithm-confusion footgun.

**Fix:** Check the actual key type, not just the base type:
```cpp
const int key_id = EVP_PKEY_id(parsed.get());
if (key_id != EVP_PKEY_RSA) {  // rejects EVP_PKEY_RSA_PSS too
    ...
}
```

---

### Finding 3: Success-path PEM buffer not explicitly wiped in server.cpp — INFO

**File:** `server/core/src/server.cpp:3019-3020`  
**What:** In the oversized-key path, the code explicitly calls `yuzu::secure_zero(key_pem)` before discarding. In the success path, `key_pem` is moved into `sp_signing_key_pem`, which is then moved into `saml_cfg.sp_signing_key_pem`, which is finally wiped by `PemCleanser` in the `SamlProvider` constructor. However, the moved-from `key_pem` itself is never wiped. With small-string optimization (SSO), the byte array may remain in the stack buffer of the moved-from string until it is overwritten.

**Impact:** Transient key material may linger in stack memory for an unbounded time. Low practical risk because (a) the final destination is wiped, (b) the process is long-lived, and (c) SSO buffers are small. But it is an inconsistency with the explicit zeroing done on the oversized path.

**Fix:** Wrap `key_pem` in a `detail::ScopedKeyZero` RAII guard (already defined in `server.cpp`) so it is zeroed on scope exit regardless of move state:
```cpp
detail::ScopedKeyZero key_zero{key_pem};
sp_signing_key_pem = std::move(key_pem);
```

---

### What I checked and found NOT exploitable

| Area | Verdict | Notes |
|------|---------|-------|
| **Signature-base correctness / signing oracle** | **Clean** | The signed octet string (`SAMLRequest=&RelayState=&SigAlg=`) is byte-identical to the sent query string. `url_encode` uses the RFC 3986 unreserved allowlist (`alnum` + `-_.~`), so attacker-controlled `RelayState` cannot inject unencoded `&` or `=` into the signed base. The `RelayState` parameter is URL-decoded by httplib and re-encoded by the same `url_encode`, so the signed bytes match the wire bytes. No forgery, cross-protocol, or split-parameter oracle is possible. |
| **Crypto: PKCS#1 v1.5 + SHA-256** | **Clean** | `rsa_sha256_sign` explicitly sets `RSA_PKCS1_PADDING` on the `EVP_PKEY_CTX` after `EVP_DigestSignInit`. The `SigAlg` URI is hardcoded to `rsa-sha256`. No algorithm confusion or padding oracle is introduced. |
| **Fail-closed / silent downgrade** | **Clean** | Boot: a bad key (`validate_key_file_permissions` fails, unreadable, oversized, malformed, non-RSA, encrypted) sets `sp_key_ok = false` and prevents `saml_provider_` construction entirely. Per-request: if `sp_signing_key_` is non-null and signing fails, `build_authn_request` returns `{}`; `auth_routes.cpp` returns 500. There is no path that emits an unsigned redirect when a signing key is configured. |
| **Private key at rest** | **Clean** | Permission check (`validate_key_file_permissions`) rejects group/other-readable. 64 KiB cap prevents unbounded reads. Encrypted keys are rejected via no-op password callback. The transit PEM is wiped by `PemCleanser` on every constructor exit path. The key is never logged. `std::shared_ptr<EVP_PKEY>` retains the parsed key; no PEM material persists in `config_` after construction. |
| **Endpoint abuse / pre-auth signing DoS** | **Mitigated** | `GET /auth/saml/start` is rate-limited under the tighter `login_rate_limiter_` bucket (`server.cpp:9287`). The signing cost is one RSA signature per request (bounded by rate limiting). No batch or streaming signing surface exists. |
| **Pinned-IdP-cert verify** | **Unchanged / no weakening** | `validate_response` is untouched. The IdP cert is still loaded via `xmlSecOpenSSLAppKeyLoadMemory` and set directly on `dsig_ctx->signKey`. |
| **XSW / assertion validation** | **Unchanged / no weakening** | Exactly-one-Assertion rule, Reference URI binding, duplicate-ID scan, and xmlAddID collision check are all unchanged. |
| **InResponseTo replay** | **Unchanged / no weakening** | `pending_requests_` storage, SHA-256 cookie-secret binding, single-use consumption, and 10-minute TTL are all unchanged. A signing failure leaves a dead entry in `pending_requests_`, but the user never receives the URL, and the random 160-bit ID is unguessable. |
| **SCIM deprovision** | **Unchanged / no weakening** | The ACS handler's `link_saml_login_to_scim` → `deprovision_deny_split` → `invalidate_user_sessions` chain is untouched. |

---

### Summary

The implementation is **fundamentally sound** and **fail-closed**. The two substantive findings are:
1. **MEDIUM:** Missing minimum RSA key size floor (accepts 1024-bit and smaller).
2. **LOW:** `EVP_PKEY_base_id` lets RSA-PSS keys slip through the documented "RSA-only" rejection.

Both are boot-time configuration hardening gaps, not runtime bypasses. The internal 13-agent governance review did not miss any critical flaws; these are the kind of residual sharp edges an independent adversarial pass is designed to catch.
