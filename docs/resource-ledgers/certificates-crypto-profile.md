# Resource Ledger — `certificates` crypto-profile columns

This ledger covers every resource the `certificates` crypto-profile change touches, on the branch
`feat/certificates-key-algorithm` from its base `52e6bb82a` to the branch tip. The change adds three
columns (`key_algorithm`, `key_bits`, `signature_algorithm`) to the existing `list` and `details` actions
on all three OS legs. A Resource Ledger is a policy-floor artifact (CLAUDE.md standing rule 2), so it is a
standalone file rather than a line in a PR description. Format follows
`docs/resource-ledgers/4666-log-handoff.md`.

Files covered: `agents/plugins/certificates/src/certificates_crypto_profile.hpp` (new),
`agents/plugins/certificates/src/certificates_x509.hpp`, `agents/plugins/certificates/src/certificates_plugin.cpp`,
`tests/unit/test_certificates_crypto_profile.cpp` (new), `tests/unit/test_certificates_x509.cpp`,
`tests/unit/test_certificates_macos_actions.cpp`. The edit to
`agents/plugins/filesystem_posture/src/filesystem_posture_legs.hpp` is a comment-only citation fix and
touches no resource.

**Negative inventory.** Nothing in this change acquires an owning resource. It adds no file descriptor,
HANDLE, SOCKET, `FILE*`, SQLite handle, owned OpenSSL object, BCrypt handle, `LocalAlloc`/`CryptDecodeObjectEx`
buffer, CF or IOKit reference, mapped library, temp path, subprocess, callback context or thread. Every
OpenSSL and CryptoAPI value the new code reads is a pointer borrowed from a certificate that an existing,
unchanged owner already holds, and every value it returns is a `std::string`, `std::optional` or plain
integer copied out before that owner releases the certificate. No new spawn site is added and no existing
spawn argv changes (ADR-3002; `docs/agent-spawn-sink-manifest.md` rows `certificates/list_certs_macos#1` and
`certificates/parse_pem_block_macos#1` are unaffected).

## `agents/plugins/certificates/src/certificates_crypto_profile.hpp`

Pure decision code: an OID table, `der_oid_to_dotted` and `describe()`. It includes only standard headers
(`<array>`, `<cstddef>`, `<cstdint>`, `<optional>`, `<span>`, `<string>`, `<string_view>`) and calls no OS or
crypto API.

| Resource | Owner | Acquire | Release | Failure path |
|---|---|---|---|---|
| Input DER OID bytes (`std::span<const std::uint8_t>`) | Caller (the CryptoAPI or OpenSSL leg below) | Borrowed for the duration of the call | Not released here | A malformed or over-long encoding returns `std::nullopt`; nothing is allocated before the check |
| Output strings (`std::string`) | Returned by value to the caller | Built in the function | Caller's scope | None needed: value types |

## `agents/plugins/certificates/src/certificates_x509.hpp` — Linux and macOS PEM legs

`extract_crypto_profile(X509* x)` runs inside `extract_all`, which is called only while the existing
`parse_pem_certs`/`parse_der_cert` RAII owner holds `x`.

| Resource | Owner | Acquire | Release | Failure path |
|---|---|---|---|---|
| `X509_PUBKEY*` from `X509_get_X509_PUBKEY(x)` | The `X509` (`get0` semantics) | Borrowed | Never freed here; freed with `x` by the existing owner | A null result skips the key OID; the column reports `(unknown)` |
| `ASN1_OBJECT*` algorithm and `X509_ALGOR*` parameters from `X509_PUBKEY_get0_param` | The `X509_PUBKEY` | Borrowed | Never freed here | A return other than 1 skips the key OID |
| Curve `ASN1_OBJECT*` from `X509_ALGOR_get0` (`pval`, only when `ptype == V_ASN1_OBJECT`) | The `X509_ALGOR` | Borrowed | Never freed here | Any other `ptype` leaves the curve unset (`EC (no named curve)`) |
| `EVP_PKEY*` from `X509_get0_pubkey(x)` | The `X509` (`get0`, not `get`, so no reference is taken) | Borrowed | Never freed here | A null result leaves the bits unset; the error OpenSSL queues for an undecodable key is cleared with `ERR_clear_error()` (`certificates_x509.hpp:306`) so it cannot leak into a later, unrelated OpenSSL call on the same thread |
| Signature `X509_ALGOR*` from `X509_get0_tbs_sigalg(x)` and its `ASN1_OBJECT*` | The `X509` | Borrowed | Never freed here | A null result reports `(unknown)` |
| `obj_to_dotted` render buffer (`char buf[...]`) | Stack frame of `obj_to_dotted` | Stack | Scope exit | `OBJ_obj2txt` returning a non-positive length, or a length that would not fit, yields an empty string (treated as unreadable), never a truncated OID |

## `agents/plugins/certificates/src/certificates_plugin.cpp` — Windows CryptoAPI leg

| Resource | Owner | Acquire | Release | Failure path |
|---|---|---|---|---|
| `const CERT_INFO*` (`cert->pCertInfo`) and its already-decoded `SubjectPublicKeyInfo.Algorithm`, `.Parameters` and `SignatureAlgorithm` blobs | The `PCCERT_CONTEXT` held by the existing store-enumeration loop (`CertEnumCertificatesInStore`/`CertFreeCertificateContext`, unchanged) | Borrowed | Never freed here | Missing fields report `(unknown)`. The algorithm OIDs are decoded with `der_oid_to_dotted` from the in-struct strings and parameter bytes, not through a `CryptDecodeObjectEx` + `LocalAlloc` round trip, so no buffer is allocated |
| `std::string_view` over `pszObjId` (key and signature OIDs) | The `PCCERT_CONTEXT` | Borrowed, local to `get_crypto_profile` | Ends when `describe()` returns; `describe()` copies everything it keeps into the `std::string` members of `CryptoProfile`, so no view outlives the certificate | A null `pszObjId` becomes an empty view, reported as `(unknown)` |
| `CertGetPublicKeyLength` result (`DWORD`) | Value | Call | None | A return of 0 means the key could not be sized and reports `(unknown)`. The `const_cast` on the `CERT_PUBLIC_KEY_INFO*` argument exists only because the prototype is non-const; the function does not write through it |

## Tests

| Resource | Owner | Acquire | Release | Failure path |
|---|---|---|---|---|
| Embedded PEM fixtures (`constexpr const char*`) | Static storage | Compile time | Never | n/a |
| `X509` objects parsed from those fixtures | The existing `parse_pem_certs` RAII owner in `certificates_x509.hpp` (unchanged) | Inside the call | Before the call returns; the tests receive `CertFields` values only | A parse failure returns no row, which the assertions catch |
| `tests/unit/test_certificates_macos_actions.cpp` additions | No new resources: the added assertions read the three new columns from rows the existing fixtures already produce. The existing salted temp keychains and the `DeniedCopy` pattern are unchanged | — | — | — |

## Trigger rows checked

- C++ resource ownership and lifetime (`.claude/routed-concerns.md`): every new pointer is borrowed, none
  outlives its owner, and no `Scoped*` owner is touched.
- Plugin README standard (`docs/plugin-readme-standard.md`): the README and its generated fences are updated
  in the same change.
