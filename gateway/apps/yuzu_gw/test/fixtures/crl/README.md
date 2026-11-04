# CRL fixtures (#6016 PR 4b)

Public material only. No private key is checked in, and none of it is a credential: the
certificates are throwaway test material, never valid for a real deployment (the CAs are valid until
2036 and the leaves until 2027-11-02, so no test here may start checking certificate validity
against the real clock without re-minting them). `yuzu_gw_mgmt_crl_watcher_tests` fails if a private
key appears in this directory, because `.gitignore` un-ignores every `*.pem` here.

The set is NOT regenerable from this repository: the CA key was thrown away after minting. A new case
(a CRL without a `cRLNumber`, a delta CRL, an `issuingDistributionPoint`, a very large list) means
re-minting every file with `build_crl`/`self_sign_ca`/`issue_leaf` as described below, then updating
`?THIS` in every test module that carries it and the dates in this file.

These are the bytes the Yuzu server's REAL CRL builder produces. The CRLs were written by
`yuzu::server::pki::build_crl` (`server/core/src/x509_ca.cpp`, unchanged since the PKI hardening
of #4833) with a validity of `now - 300 s .. now + 48 h` (the shape `CrlPublisher::publish` uses
since #6016 step 4d), signed by an EC P-384 CA whose certificate came from `pki::self_sign_ca`
with subject `O=Yuzu, CN=Yuzu Install CA`. `server.pem` is a leaf issued by `pki::issue_leaf`
with `serverAuth`, `clientAuth` and the URI SAN `yuzu://AAAA/server`.

| File | What it is |
|---|---|
| `root-ca.pem` | the self-signed install CA |
| `server.pem`, `server.serial` | a server leaf under it and its serial (hex) |
| `other.pem` | a second leaf under it (no URI SAN), NOT revoked |
| `crl-populated.der` | cRLNumber 7, lists the serial in `server.serial` |
| `crl-empty.der` | cRLNumber 8, no revoked entries |
| `sub-ca.pem` | a subordinate-shaped certificate: the SAME key and subject as `root-ca.pem`, issued by `CN=Enterprise Root,O=Corp`, with a different SKI (the subordinate-CA import case) |
| `crl-sub.der` | cRLNumber 9, built from `sub-ca.pem`; its AKI does not match `root-ca.pem`'s SKI |
| `evil-ca.pem` | a CA with the SAME subject DN as `root-ca.pem` and a DIFFERENT key |
| `crl-evil.der` | cRLNumber 99, signed by that other key, naming the same issuer DN |
| `renamed-ca.pem` | a self-signed certificate over the SAME key as `root-ca.pem` with a DIFFERENT subject (`O=Yuzu, CN=Renamed Install CA`), made on 2026-11-03 with `openssl req -new -x509` from the throwaway CA key (not by the C++ builder). A CRL from `root-ca.pem` verifies against it by signature but names a different issuer |

The times are fixed in the files (thisUpdate 2026-11-02 14:14:48Z). Tests that depend on the clock
inject `now`; nothing here reads the wall clock. The CRLs' own `nextUpdate` is 2026-11-04T14:19:48Z,
so a test that calls `check` with the real clock would start refusing as `revocation_stale` on
2026-11-05T14:19:48Z: none does, and none may.
