# TLS Policy

This page describes the TLS version floor and cipher allow-list Yuzu pins
across its listeners, and precisely what's proven by CI versus what's
disclosed as a known gap. See [Server Administration](server-admin.md#tls-configuration)
for how to configure the underlying certificates.

## What's pinned

Every listener below negotiates **TLS 1.2 or higher** and, when TLS 1.2 is
negotiated, is restricted to this six-suite allow-list (all ECDHE, so every
negotiated session has forward secrecy; both ECDSA and RSA families so
operator-supplied RSA certificates keep working):

```
ECDHE-ECDSA-AES256-GCM-SHA384
ECDHE-ECDSA-AES128-GCM-SHA256
ECDHE-ECDSA-CHACHA20-POLY1305
ECDHE-RSA-AES256-GCM-SHA384
ECDHE-RSA-AES128-GCM-SHA256
ECDHE-RSA-CHACHA20-POLY1305
```

| Surface | Pinned by | Proven by |
|---|---|---|
| Agent gRPC listener (`:50051`) | `GRPC_SSL_CIPHER_SUITES` (process env, pinned before any gRPC call) | `test_grpc_tls_policy.cpp` — real loopback handshakes |
| Management gRPC listener (`:50052`) | Same env pin (shared gRPC process state) | Same suite (same credential builder) |
| Gateway-command client (server → gateway mTLS) | Same env pin | `test_grpc_tls_policy.cpp` — outbound cases against a raw TLS server |
| HTTPS dashboard listener (`:8443`) | `SSL_CTX_set_cipher_list` applied directly to httplib's `tls_context()` right after listener construction | Manual `openssl s_client` probe (see below) — **not** a handshake unit test in this PR |
| Certificate hot-reload validation context | Same cipher list applied to the reload's temporary validation `SSL_CTX` | `test_cert_reloader.cpp`'s live-`SSLServer` reload case (validates the cipher list survives a hot-swap) |

**Agent side is NOT pinned by this change.** `agents/core`'s own gRPC client
credentials still negotiate whatever gRPC's library default offers
(AEAD-only suites, TLS 1.2 floor) — the agent side is not yet pinned; tracked
under [#4722](https://github.com/Tr3kkR/Yuzu/issues/4722).

## Why a process environment variable

gRPC's C++ credentials API (`grpc::SslServerCredentialsOptions`,
`grpc::SslCredentialsOptions`, and the experimental
`TlsCredentialsOptions`) has no cipher or ciphersuite setter. The only lever
gRPC exposes is the `GRPC_SSL_CIPHER_SUITES` environment variable, read once
by `grpc_core::ConfigVars` on first use and applied internally via
`SSL_CTX_set_cipher_list`. Ordering therefore matters: the server pins this
variable before constructing anything that could touch gRPC, and unconditionally
overwrites whatever the process inherited — an operator- or
container-supplied value for `GRPC_SSL_CIPHER_SUITES` is never honoured.

## TLS 1.3 is not pinned by this mechanism

`SSL_CTX_set_cipher_list` (and therefore `GRPC_SSL_CIPHER_SUITES`) only
governs TLS 1.2 and earlier cipher *suites*. TLS 1.3 ciphersuite selection
uses a separate OpenSSL API (`SSL_CTX_set_ciphersuites`) that gRPC's
credentials layer never calls on any code path, so a TLS 1.3 handshake
always negotiates whichever of OpenSSL's own default suites
(`TLS_AES_128_GCM_SHA256` / `TLS_AES_256_GCM_SHA384` /
`TLS_CHACHA20_POLY1305_SHA256`) both sides offer. The server's startup log
says this explicitly rather than implying TLS 1.3 is covered.

## Startup log lines

On every start, once the version banner has printed, the server logs:

```
TLS policy: TLS 1.2 cipher list pinned for gRPC and HTTPS: ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-CHACHA20-POLY1305
TLS policy: TLS 1.3 suites are OpenSSL's own default (...) — gRPC never calls SSL_CTX_set_ciphersuites on any credentials API, so TLS 1.3 suite selection is not pinned
```

If the allow-list resolves to zero usable TLS 1.2 ciphers against the
OpenSSL build actually linked (a boot self-check, distinct from the log
lines above), the server logs a `critical` message and refuses to start
rather than silently serving with no effective policy.

**If you hit this refusal.** The `critical` line names which of three causes
fired: the throwaway `SSL_CTX` failed to construct, `SSL_CTX_set_cipher_list`
rejected the compile-time literal, or the list resolved to zero TLS 1.2
ciphers actually available in the linked OpenSSL build. The allow-list is a
compile-time literal with no runtime override — there is no flag or
environment variable that changes it — and this condition cannot be produced
by any operator configuration; it means the OpenSSL library the server
actually linked against no longer provides any of the six pinned suites.
Restore the shipped OpenSSL library files (reinstall or repair the package),
or roll back to the previous release, and report it as a build/packaging
defect.

## What CI asserts

`tests/unit/server/test_grpc_tls_policy.cpp` drives the production
credential builders (`yuzu::server::detail::build_server_tls_credentials`,
`build_mtls_client_credentials`) over real loopback TLS/mTLS handshakes.
Every negative case asserts genuine refusal by the peer — either a received
TLS alert, or (where this OpenSSL/gRPC build closes the connection instead
of emitting an alert record) `SSL_R_UNEXPECTED_EOF_WHILE_READING` following
a successful TCP connect — never a probe that merely failed locally:

- **TLS 1.0 only** and **TLS 1.1 only** — refused independently.
- **Non-allow-listed but leaf-compatible ciphers** — refused, with a
  same-shape positive control on an allow-listed cipher.
- **Certless client** against a listener requiring one — refused, with a
  positive control presenting the trusted client leaf.
- **Plaintext client** against the TLS listener — refused, with a positive
  control proving the probe recognises a real plaintext HTTP/2 server.
- **Wrong-CA client certificate** (inbound) — refused, both via the raw
  probe and via the production gRPC client credentials landing in
  `TRANSIENT_FAILURE`.
- **Wrong-CA gateway impersonator** (outbound) — the production client
  credentials refuse a server presenting a leaf from an untrusted CA.
- **Outbound cipher enforcement** — the production client credentials,
  forced to TLS 1.2, negotiate a pinned-only suite (proving the env pin
  governs the client direction too) and refuse a server offering only a
  non-allow-listed cipher.

`tests/unit/test_tls_policy.cpp` (agent suite; pure, no network) pins the
allow-list's exact text and ordering, both ECDSA and RSA families being
present, and `resolve_cipher_policy`'s refusal on an unresolvable list.

`tests/unit/server/test_cert_reloader.cpp` proves the cipher pin survives a
live certificate hot-swap on a real `httplib::SSLServer`.

**The HTTPS listener's pin itself has no automated handshake test in this
PR** — its fail-closed branch (`SSL_CTX_set_cipher_list` failing on an
already-valid `SSL_CTX`) is impossible in practice with a fixed compile-time
literal. Evidence for the HTTPS pin is the manual `openssl s_client` probe
below, plus the reload test's live-context assertion.

## Manual verification

```bash
# TLS 1.1 refused on the agent listener
openssl s_client -connect 127.0.0.1:50051 -tls1_1

# A non-allow-listed cipher refused on TLS 1.2
openssl s_client -connect 127.0.0.1:50051 -tls1_2 -cipher ECDHE-ECDSA-AES128-SHA256

# An allow-listed suite outside gRPC's OWN default negotiates (proves the pin)
openssl s_client -connect 127.0.0.1:50051 -tls1_2 -cipher ECDHE-ECDSA-CHACHA20-POLY1305

# Same non-allow-listed-cipher refusal on the HTTPS dashboard listener
openssl s_client -connect 127.0.0.1:8443 -tls1_2 -cipher ECDHE-ECDSA-AES128-SHA256

# Confirms the production entrypoint's unconditional overwrite and ordering:
# an inherited GRPC_SSL_CIPHER_SUITES must NOT survive.
GRPC_SSL_CIPHER_SUITES=ECDHE-ECDSA-AES128-GCM-SHA256 ./yuzu-server ...
openssl s_client -connect 127.0.0.1:50051 -tls1_2 -cipher ECDHE-ECDSA-CHACHA20-POLY1305
# still negotiates -> the server's own pin overwrote the inherited value.
```

## Known follow-up

The production-entrypoint ordering (the pin running before gRPC's first
use in the real `yuzu-server` binary, as opposed to the test executable's
own independent static-initialiser pin) and the HTTPS listener's direct
cipher application are both verified manually above, not by an automated
test — the unit test executable pins from its own static initialiser and
cannot observe `main.cpp`'s ordering, and no test performs a real handshake
against `start_web_server()`'s listener. An automated assertion for both is
tracked as [#4740](https://github.com/Tr3kkR/Yuzu/issues/4740) against the
`scripts/integration-test.sh` TLS mode (roadmap PR 1).

The agent side is not yet pinned; tracked under
[#4722](https://github.com/Tr3kkR/Yuzu/issues/4722). Any future work there can
reuse `tests/unit/tls_probe.hpp` unchanged.
