# Resource Ledger: OIDC sign-in browser binding (branch fix/oidc-browser-binding)

Range `997e887fb..HEAD` (the fix round adds one commit on top of the two feature commits). C++ files changed:
`server/core/src/auth_routes.cpp`, `oidc_provider.{hpp,cpp}`, `evp_raii.hpp` (comment only) and the tests
`tests/unit/server/test_oidc_provider.cpp`, `test_oidc_routes.cpp`, `test_oidc_mock_idp.hpp` (new). No new source file is
added to a `meson.build`. A Resource Ledger is required on a C++ diff (governance SKILL.md Gate 1).

Basis and limits. This ledger is reading, `grep` and `git`; the tests named in the run record were executed separately. The
Windows (`_WIN32`) branch of `sha256_raw` was NOT compiled on the Linux development host.

## Summary verdict

No new fd, `FILE*`, SOCKET, sqlite object, subprocess, temp path, mapped library or allocated C string. New owned resources:
one OpenSSL digest context (RAII), two CNG handles on Windows only (RAII), and, in tests only, one listening socket plus
thread, two process-static OpenSSL key objects and a few `unique_ptr` temporaries. There is no manual cleanup in new C++.

## Production

| # | Resource | Where | Owner type | Acquired | Released | Transfer | Failure cleanup |
|---|---|---|---|---|---|---|---|
| P1 | `EVP_MD_CTX` for the SHA-256 digest | `oidc_provider.cpp` `sha256_raw`, POSIX branch | `EvpMdCtxPtr` (`unique_ptr` with `EVP_MD_CTX_free`, `evp_raii.hpp`) | `EVP_MD_CTX_new()` in the `if` initialiser | scope exit of that `if` | none; move-only, never copied or returned | a null context skips the digest and `sha256_raw` throws; each `EVP_Digest*` return is checked and a failed step leaves `ok` false, so the scope exit still frees the context and the function throws |
| P2 | CNG algorithm provider handle | `oidc_provider.cpp` `BcryptAlgHandle`, Windows only (anonymous namespace) | `BcryptAlgHandle` (non-copyable, non-movable) | `BCryptOpenAlgorithmProvider(alg.out(), ...)` | destructor calls `BCryptCloseAlgorithmProvider` if the handle is non-null | none | a failed open leaves the handle null and the destructor does nothing |
| P3 | CNG hash handle | `oidc_provider.cpp` `BcryptHashHandle`, Windows only (anonymous namespace) | `BcryptHashHandle` (non-copyable, non-movable) | `BCryptCreateHash(alg.get(), hh.out(), ...)` | destructor calls `BCryptDestroyHash` if non-null; declared after `alg`, so destroyed before the provider handle | none | a failed create leaves it null; a failed hash step sets `ok` false and the scope exit destroys both handles in reverse order |
| P4 | Digest output buffer | `sha256_raw` | `std::vector<uint8_t>` | construction | scope exit | returned by value | thrown away on the throw path; never exposed when `ok` is false |
| P5 | Pending-flow map entries (`PkceChallenge` incl. `binding_hash`) | `OidcProvider::pending_challenges_` | the map, guarded by `mu_` | `start_auth_flow` (after the digest succeeded) and `add_test_pending_flow` (test seam) | erased on a matched callback, on expiry, on capacity eviction (oldest) and in `cleanup_expired_states` | the entry is MOVED out of the map under the lock on a match; a refused callback leaves it in place by design | a digest failure at start throws before anything is stored, so no entry leaks |
| P6 | Binding secret string | `start_auth_flow` / the route | `std::string` in `AuthFlowStart` | CSPRNG bytes hex-encoded | route scope exit; only its digest is retained server-side | moved from the provider to the route, written into one `Set-Cookie` header | `random_bytes` or digest failure throws; the route answers 500 and sets no cookie |
| P7 | Binding-digest test flag | `OidcProvider::binding_digest_forced_failure_` | `std::atomic<bool>` member | member init | member destruction | none | not a resource; listed because it is a test seam in production code, pinned by a source-scan test |

No lock is held across the digest in `handle_callback` (the presented secret is hashed before `mu_` is taken), and no callback
context, thread or allocation is introduced in production code.

## Tests

| # | Resource | Where | Owner type | Acquired | Released | Notes |
|---|---|---|---|---|---|---|
| T1 | Listening socket + acceptor thread | `test_oidc_mock_idp.hpp` `MockIdp` | the `MockIdp` object (copy deleted) | `bind_to_any_port` (no fixed port) and `std::thread` in the constructor | destructor: `svr.stop()` then `thread.join()` | compiled out under ThreadSanitizer (`YUZU_OIDC_MOCK_IDP_TSAN`); the only constructor early exit (`REQUIRE(port > 0)`) comes before the thread starts, so there is no thread to join on that path |
| T2 | RSA test key (`EVP_PKEY`) | `SharedRsaKey` / `shared_rsa_key()` | `unique_ptr<EVP_PKEY, ... EVP_PKEY_free>` in a function-static | first call | process exit | one key per process, never freed earlier |
| T3 | `BIGNUM` n and e | `shared_rsa_key()` | `unique_ptr<BIGNUM, ... BN_free>` x2 | `EVP_PKEY_get_bn_param` | end of the initialiser lambda | encoded to base64url before release |
| T4 | `EVP_MD_CTX` for RS256 signing | `sign_and_register_rs256` | `unique_ptr<EVP_MD_CTX, ... EVP_MD_CTX_free>` | `EVP_MD_CTX_new()` | function exit | every early `return ""` still frees it |
| T5 | Cookie-jar and rig objects | `Browser`, `BindingRig` in `test_oidc_routes.cpp` | value members; `BindingRig` owns a `MockIdp`, an `OidcRoutesFixture` and the provider (`unique_ptr`) | construction | scope exit | the rig declares `idp` first, so the fixture and provider are destroyed before the token endpoint stops |
| T6 | Pending-flow entries in tests | via `start_auth_flow` / `add_test_pending_flow` | the provider under test | per case | provider destruction | none outlive the test |
| T7 | Test seam toggle | `DigestFailure` guard in `test_oidc_provider.cpp` | RAII struct, copy deleted | constructor sets the flag | destructor clears it, including when an assertion throws | the routes test sets and clears it by hand around a single dispatch; the provider is function-local, so nothing leaks past the case |

## Ownership notes

- The fix round changed the digest-failure return of `handle_callback` from the mismatch token to a distinct fixed token; no
  ownership changed.
- `verify_jwt_signature` still frees its own `EVP_MD_CTX` by hand. That is pre-existing code in a file this change merely
  touches (SHOULD, not a floor); it is untouched and the `evp_raii.hpp` banner says so.
- `sha256_raw`'s own failure branch (a provider return code) cannot be reached from a test; the test seam fires in
  `binding_digest` before it, so the caller's fail-closed handling is exercised and `sha256_raw`'s branch is covered by reading only.
