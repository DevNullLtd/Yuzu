Warning: Unknown toolsets: messaging

session_id: 20260814_194018_097c83
Independent adversarial review complete. I found **four actionable findings** (one HIGH, one MEDIUM, two LOW) plus two informational items. The internal 13-agent review missed the key-size floor and the amplification-DoS surface; the hardening round missed the Windows-stub hygiene gap.

---

## 1. HIGH — Missing RSA key-size floor accepts weak keys

**Location:** `server/core/src/saml_provider.cpp:596-606`

**Issue:** After parsing a PEM private key and confirming `EVP_PKEY_base_id == EVP_PKEY_RSA`, the code immediately retains the key without checking its modulus size. A 512-bit or 1024-bit RSA key is accepted silently. Such keys are factorable in hours (1024-bit) or minutes (512-bit) on modern hardware, allowing signature forgery and IdP impersonation.

**Concrete exploit:** An operator mistakenly deploys a 1024-bit test key via `--saml-sp-key`. An attacker who observes a signed AuthnRequest can factor the public modulus and forge arbitrary AuthnRequests, bypassing the SP→IdP authentication binding.

**Fix:** After the `EVP_PKEY_RSA` check, add:
```cpp
if (EVP_PKEY_bits(parsed.get()) < 2048) {
    signing_init_failed_ = true;
    signing_init_error_ = "SAML SP signing key must be at least 2048 bits";
    spdlog::error("SamlProvider: {}", signing_init_error_);
}
```

---

## 2. MEDIUM — Unthrottled pre-auth signing amplification DoS

**Location:** `server/core/src/auth_routes.cpp:2840`

**Issue:** `GET /auth/saml/start` is pre-authentication and unthrottled. When `--saml-sp-key` is configured, every request triggers an RSA PKCS#1 v1.5 signing operation (single-shot SHA-256 + modular exponentiation). RSA signing is ~100× more CPU-expensive than verification. A moderate request flood (e.g., thousands of parallel unauthenticated requests) can exhaust CPU and starve legitimate traffic.

**Concrete exploit:** `curl -Z -j100 -n10000 'https://target/auth/saml/start'` or equivalent botnet load forces the server to perform 10,000 RSA signings, saturating cores.

**Fix:** Add per-IP rate limiting or a global token bucket to `/auth/saml/start`. A leaky-bucket of e.g. 10 requests/minute per IP (with burst 3) is sufficient; unsigned requests (no key configured) can remain more permissive since they skip the crypto.

---

## 3. LOW — Windows stub fails to wipe transit PEM

**Location:** `server/core/src/saml_provider.cpp:14-16`

**Issue:** The Windows stub constructor moves `SamlConfig` (including any `sp_signing_key_pem`) into `config_` but does **not** include the `PemCleanser` RAII guard that the non-Windows constructor uses. If a caller directly instantiates `SamlProvider` on Windows with a PEM (e.g., in a future test or cross-platform refactor), the raw private-key bytes linger in the `config_` member for the object’s lifetime.

**Concrete impact:** Low in current deployment (server.cpp never constructs the provider on Windows), but violates the “wipe on all paths” invariant and could leak key material in a future Windows-port test.

**Fix:** Add the same `PemCleanser` struct and declaration to the Windows stub:
```cpp
SamlProvider::SamlProvider(SamlConfig config) : config_(std::move(config)) {
    struct PemCleanser { std::string& pem; ~PemCleanser() { yuzu::secure_zero(pem); } }
        pem_cleanser{config_.sp_signing_key_pem};
    spdlog::info("SamlProvider: SAML is not supported on Windows — provider disabled");
}
```

---

## 4. LOW — Uncapped RelayState length

**Location:** `server/core/src/auth_routes.cpp:2853`

**Issue:** `req.get_param_value("RelayState")` is passed verbatim to `build_authn_request` with no length cap. An attacker can supply a multi-megabyte RelayState, causing:
- An oversized redirect URL (browser/IdP rejection, potential truncation)
- Increased memory consumption in the signing base string
- Log amplification if the RelayState is ever logged (it is not currently, but future code might)

SAML 2.0 profiles recommend RelayState ≤ 80 bytes.

**Concrete exploit:** `GET /auth/saml/start?RelayState=<1MB-of-junk>` creates a ~1.3 MB signed base string and redirect URL.

**Fix:** Cap RelayState before passing to `build_authn_request`:
```cpp
if (relay_state.size() > 512) relay_state.resize(512); // or reject with 400
```

---

## 5. LOW — OpenSSL error queue not cleared after failed key parse

**Location:** `server/core/src/saml_provider.cpp:586-593`

**Issue:** When `PEM_read_bio_PrivateKey` fails (encrypted key, malformed PEM), OpenSSL pushes detailed error strings to the thread-local error queue (`ERR_get_error`). The code logs a generic message but never calls `ERR_clear_error()`. Subsequent OpenSSL operations on the same thread that check the error queue may misinterpret stale errors as their own, or leak operation details (e.g., “bad decrypt” revealing that a passphrase-protected key was attempted).

**Fix:** After logging the parse failure, add:
```cpp
ERR_clear_error();
```

---

## 6. INFO — Missing RSA-PSS key rejection test

**Location:** `tests/unit/server/test_saml_provider.cpp`

**Issue:** The test suite covers EC key rejection (`generate_ec_key_pem`) and encrypted-key rejection, but does **not** test that an RSA-PSS key (EVP_PKEY_RSA_PSS on OpenSSL 3.x) is rejected. In OpenSSL 1.x, an RSA-PSS key may still present as `EVP_PKEY_RSA` but disallow PKCS#1 v1.5 padding; without a test, a regression that accidentally accepts such a key would only be caught at runtime signing failure.

**Fix:** Add a `generate_rsa_pss_key_pem()` helper (generate RSA-PSS restricted key via `EVP_PKEY_CTX_set_rsa_pss_keygen_md`) and a test asserting `signing_configured_but_broken() == true`.

---

## Areas checked and confirmed safe

| Area | Verdict | Evidence |
|------|---------|----------|
| **Signature-base correctness** | **Safe** | Signed base is `SAMLRequest=[enc]&RelayState=[enc]&SigAlg=[enc]` (RelayState omitted when empty, never `RelayState=`). `url_encode` allowlist is `alnum + -_.~`; `&` and `=` are always percent-encoded, so no injection or parameter splitting. The sent query string and signed base are byte-identical. |
| **Signing-oracle / cross-protocol** | **Safe** | Attacker controls only RelayState (bounded prefix `SAMLRequest=…` and suffix `&SigAlg=…`). No useful forgery or cross-protocol signature transplantation possible. |
| **Algorithm confusion (SigAlg vs key type)** | **Safe** | `EVP_PKEY_base_id != EVP_PKEY_RSA` rejects EC and RSA-PSS. `rsa_sha256_sign` explicitly sets `RSA_PKCS1_PADDING` after `EVP_DigestSignInit`. No downgrade to PSS or `alg:none` possible. |
| **Fail-closed boot path** | **Safe** | Bad key → `signing_init_failed_` → `signing_configured_but_broken()` → server.cpp resets provider and disables SAML loudly. No silent unsigned fallback. |
| **Fail-closed per-request path** | **Safe** | `rsa_sha256_sign` failure → `sig.empty()` → `build_authn_request` returns `{}` → auth_routes.cpp returns 500. Never emits unsigned redirect when key is configured. |
| **Pinned-IdP verify / XSW / InResponseTo / SCIM** | **Safe** | `validate_response` is untouched by this diff. No SP signing state leaks into assertion verification. SCIM deprovision linkage (`saml_scim_link.hpp`) is unaffected. |
| **Private-key at-rest hygiene** | **Safe** | `validate_key_file_permissions` gates file read. 64 KiB cap. Transit PEM wiped by `PemCleanser` on every constructor exit path. Encrypted keys rejected via no-op password callback. Key is never logged. |
| **Auth-bypass / forced-browsing** | **Safe** | `/auth/saml/start` is pre-auth by design (SSO initiation). `/saml/acs` requires valid `SAMLResponse` + binding cookie; forced-browsing without both is rejected. Signing does not weaken ACS validation. |

---

**Bottom line:** The design is sound, but the implementation lacks a **key-size floor** (HIGH) and **rate limiting** (MEDIUM). The Windows stub and error-queue hygiene are LOW-impact gaps that should be closed for completeness. No auth bypass, no signing oracle, no algorithm confusion, and no silent downgrade was found.
