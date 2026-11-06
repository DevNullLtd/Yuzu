# Security review: gateway management plane authorizes the server by a CA-issued identity (#6016)

**Date:** 2026-10-18
**Subject:** the gateway's management listener (`:50063`, server to gateway command fan-out) admits
the C++ server by the exact URI SAN `yuzu://<install>/server` that the install CA mints only onto
the `default-server` leaf, as an alternative to, or on top of, the SPKI pin of #1422. A serial
deny-list withdraws a certificate. Decision record: [ADR-2004](../adr/2004-gateway-mgmt-server-identity.md).
**Base:** `feat/gateway-grpc-client` (#5695) at `f1e4842ef`, which contains the server half (#6072).
**Operator guide:** [Gateway: authorizing the server by its identity](../user-manual/gateway.md);
upgrade steps: [Upgrading](../user-manual/upgrading.md).
**Purpose of this record:** state what the pin protected and what the identity protects, where the
two differ, which differences are accepted, and what remains open, so that the accepted regressions
are not read as oversights and the mechanisms rejected here are not re-added by default.

## Provenance and limits of this record

- **Design review.** The plan was reviewed adversarially by the `enterprise-architect` validator
  (Fable tier), which returned *approve with changes*; every required change is folded into the
  design recorded here (the serial-keyed deny-list, the rejection of "admit when no CRL has been
  fetched", the single-certificate derivation rule, the explicit comparison contract). **That
  review is not retained as an artifact**; only its effect on the design is.
- **Empirical checks run on this change** (not review claims): the unit and property-style cases in
  `yuzu_gw_mgmt_identity_tests` (negative URI vectors, mode matrix, deny-list, same-key re-issue);
  the real stack in `scripts/integration-test.sh --tls --gateway-ct`, where the real C++ server
  commanded a real agent through a real gateway and all 301 forwarded commands were admitted **by
  identity** with none falling back to the pin (the gateway's derivation of the install identity from
  the CA file byte-matches what the C++ server minted), and the management Common Test suite
  minted, with the install CA's key, a leaf over a **new key**, a **same-key re-issue**, and leaves
  naming **another install** and an **agent URI**, and observed them admitted, admitted, refused and
  refused; and promtool behaviour cases for the new alert reasons.
  Those real-stack checks pre-date PR 4b: the CRL check (`mgmt_crl_source`) was **not** run on the real
  stack, because `scripts/integration-test.sh` sets no source and no Common Test case covers it; PR 4b's
  evidence is the unit, watcher and configuration tests and promtool.
- **Governance (this run) found, and this record reflects:** the default-mode trap (an unset mode with
  no pins used to select the identity), the implicit activation of the identity under a bring-your-own
  CA, and the unbound bundle case were each found by reviewers independently before merge. They are
  closed by three changes: an unset mode is always `pin` and the shipped configs ship `pin`; the
  identity is an explicit opt-in with the issuance-policy caveat stated; and an identity over a CA
  bundle needs `identity` mode with a pin (`identity_over_ca_bundle`). The governance run is the
  committed ledger `governance.d/6016-gateway-mgmt-identity.*.jsonl` (the random suffix is generated at
  commit time); the passes that followed are recorded there.
  *(Release N statement "the shipped configs ship `pin`" is superseded in part by the Amendment (release N+1) below; an unset mode is still `pin`.)*
- **Not independent review.** The governance pipeline and the external model passes that follow this
  record are recorded in that ledger; they are models, not human reviewers.
- **Risk acceptance.** This record marks three consequences as accepted: (1) a CA-key-only holder can
  command the fleet under the shipped `identity` default; (2) withdrawal is a serial in
  `mgmt_peer_denied` plus a gateway restart, and revoking the certificate in the CA inventory alone
  does nothing, **until a gateway sets `mgmt_crl_source` (PR 4b, ADR-2004 amendment): the CRL then
  withdraws it, and this acceptance stays open only for a gateway that does not set it**; (3) an own-certificate install
  that takes the new shipped config loses its command plane (`no_uri_san`) until it sets `pin`. The author does not approve their own risk acceptance. The acceptance is recorded
  by the approving reviewer on the pull request, with a review-by date to be set there. This record
  carries neither a name nor a date for it.

## What the pin protected

1. **A stolen gateway key.** The gateway's leaf is signed by the same CA, carries serverAuth, has the
   same DNS/IP names as the server's, and its key is group-readable in the shared cert volume.
   Chain, EKU and names cannot tell it from the server; the pin (and now the identity) can.
2. **A stolen or hostile agent leaf.** Agents choose their `agent_id`, which lands in the CN. The pin
   did not depend on the CN. The identity does not either: `sign_agent_csr` ignores the CSR's SAN and
   emits only `yuzu://<install>/agent/<id>` with clientAuth only, and a lexical gate
   (`tests/test_server_identity_uri_lexical.py`) confines who may mint the server URI or call the
   signer.
3. **Withdrawal of a rotated or compromised server key**, by replacing or removing the pinned file.
4. **A compromise of the CA key alone**: the pin still required the server's private key.

## Threat model: what differs

| Attacker holds | Pin | Identity | Identity and a pin |
|---|---|---|---|
| a gateway key, or an agent key | refused | refused | refused |
| the server's key (its certificate is public, so it can present it) | admitted | admitted | admitted |
| the CA key only | refused (no server key) | **admitted** (can mint the URI) | refused (no server key) |
| the server key and the CA key | admitted | admitted | admitted |
| a CA other than the Yuzu install CA that lets a requester choose a URI SAN (a bring-your-own corporate CA, as a single certificate or as part of a bundle) | refused (no server key) | **admitted** (the requester mints the URI) | refused (no server key) |

The CA-key-only row is the one change. A pin made the server's private key necessary; the identity makes a
certificate from the install CA necessary. In the **default deployment** the CA key and the server
key are both `0600` files in the same certificate directory on the server host (the directory is
`0700`, or `0750` with `--cert-group`; of the private keys only the gateway's is group-readable, and
the compose gateway container mounts the volume read-only and cannot read the CA or server key), so
an attacker who has one almost always has both, and a CA-key holder can already mint agent certificates and impersonate the server to every
agent: the narrowed case ("server key leaked, CA key intact") is small, and a CA-key compromise is a
re-root either way. A deployment that keeps the CA key apart from the server key (a hardware-backed
`KeyProvider`) loses that separation on this hop in `identity` and `identity_or_pin`. Such a
deployment should stay in `pin`, or use `identity` **with** a pin, which requires both. **This is an
accepted regression, chosen for key renewal with no gateway action; it is the reason the identity
is an explicit opt-in and `pin` is the default (an unset `mgmt_peer_auth_mode` is always `pin`, and the
shipped reference configs set `{mgmt_peer_auth_mode, pin}` (release N)).**

*Release N text: superseded in part by the Amendment (release N+1) below, which sets `identity` in the shipped configs; an unset key is still `pin`.*

The corporate-CA row is the same trust shift by another route: the identity is the CA's claim that only
the server holds the URI, and the identity trusts the issuing CA's issuance policy. The install CA
enforces that policy in code. A CA that does not (any CA in a `cacertfile` bundle, or a single
corporate CA that lets a requester choose a URI SAN with serverAuth) does not, and the gateway cannot
tell. A bundle, and any `cacertfile` that is not demonstrably exactly one readable certificate (empty,
unreadable or half-written at boot), is therefore refused at boot unless the mode is `identity` with a
pin (`identity_over_ca_bundle`); a single-certificate corporate CA is not detectable, so the identity must
not be enabled there. A pin is immune to both.

## Fail-closed rules and the test that pins each

| Rule | Reason | Pinned by |
|---|---|---|
| a peer without the identity is refused | `no_uri_san` / `identity_mismatch` | `yuzu_gw_mgmt_identity_tests` (every near-miss form) |
| unresolved identity refuses every peer that needs it | `identity_unresolved` | `yuzu_gw_mgmt_identity_tests`, `check_mgmt_auth_config_test_` |
| comparison is byte-exact on any one URI SAN | `identity_mismatch` | lower-case install, `/server/`, `/Server`, `/servers`, `/agent/server`, `/server%00`, `/server/extra`, other install, other scheme, agent URI |
| serverAuth is required in every mode | `missing_server_auth_eku` | right URI without serverAuth |
| `identity` mode with a pin requires both, including a pinned key that carries no URI (refused `no_uri_san`) | `pin_mismatch` / `no_pins_resolved` / `no_uri_san` | `yuzu_gw_mgmt_identity_tests` "identity mode with a pin: BOTH must hold" |
| in `identity_or_pin` with pins configured, when both paths fail because the peer has no identity the pin's reason is reported (the identity's only when no pin is configured) | `pin_mismatch` / `no_pins_resolved` | `yuzu_gw_mgmt_identity_tests` "identity_or_pin: the identity alone, or the pin alone, admits" |
| in `identity_or_pin` an unresolved identity is reported as itself, not as the pin's reason, when the pin does not admit the peer (a configuration defect, not a rotation) | `identity_unresolved` | `yuzu_gw_mgmt_identity_tests` "identity_or_pin with an unresolved identity is the pin mode" |
| in `identity_or_pin` a pin that never resolved is reported even while the identity admits the traffic | counter `yuzu_gw_mgmt_auth_pin_unresolved_total` | `yuzu_gw_mgmt_identity_tests` "identity_or_pin: a dead pin is reported even while the identity admits" |
| a denied serial is refused on every admission path | `revoked` | identity, `identity_or_pin`, `pin` |
| the deny-list is by serial: a same-key re-issue stays admitted | | `withdrawal is by SERIAL` case |
| when a deny-list is configured, an unreadable serial of an otherwise admitted peer is refused (with an empty list the serial is not read; the same decode already succeeded for the SPKI, EKU and SAN checks) | `revoked` | `yuzu_gw_mgmt_identity_tests` "a serial that cannot be read is refused when a deny-list is configured" |
| an unset mode is the pin mode, so a configuration with no pins and no mode still refuses the boot on an exposed listener (the identity is never implied by a missing key; unchanged in release N+1) | `no_mgmt_peer_pins` | `yuzu_gw_mgmt_identity_tests` "unset mode is ALWAYS the pin mode"; `yuzu_gw_app_tests` "unset: the pin mode, with or without pins" |
| an identity over a `cacertfile` that is not demonstrably exactly ONE readable certificate (more than one, or empty, unreadable or half-written at boot; the listener re-reads the file when it starts) refuses the boot unless the mode is `identity` AND a pin is configured (the pin must then also match) | `identity_over_ca_bundle` | `yuzu_gw_mgmt_identity_tests` "an identity over a CA file that is not demonstrably ONE certificate needs mode identity AND a pin"; `yuzu_gw_app_tests` "a CA bundle derives nothing: the listener is refused, naming the identity" |
| `mgmt_peer_identity` set while the mode is `pin` is ignored, and the boot logs a warning saying so | | `yuzu_gw_app_tests` "an identity set without the mode is ignored, and says so" |
| an explicit identity that differs from the one derived from the listener's `cacertfile` boots with a warning (a case-only difference gets a hint); the deny-list is logged as the upper-case hex it parsed to (so a decimal serial shows what is actually denied) | | `yuzu_gw_app_tests` "an explicit identity that differs from the derived one is warned of (and its case noted)", "the deny-list is logged as the upper-case hex it parsed to" |
| (release N; superseded in part by the Amendment (release N+1) below) the shipped reference configs are in `pin` mode and resolve cleanly | | `yuzu_gw_config_posture_tests` (`check_strict`, per shipped config) |
| a malformed mode, identity or deny entry (including a deny-list that is not a proper list) refuses the boot | | `check_mgmt_auth_config_test_`; PCRE `$` would admit a trailing newline, so the patterns are anchored `\A`/`\z` |
| two management listeners deriving different identities refuse the boot | | `check_mgmt_auth_config_test_` |
| an exposed listener with no way to admit the server refuses the boot | `no_mgmt_peer_*` | `evaluate_mgmt_posture/4` cases per mode |
| the identity is a bundle-safe derivation: exactly one certificate in `cacertfile` | | bundle and missing-file cases |

## Residual risks and known limits

1. **CA-key holder commands the fleet in the identity modes** (above). Accepted; mitigation is the
   mode choice.
2. **Interim loss of automatic withdrawal.** A `cert_file` pin withdrew a key within one refresh
   interval. An identity-mode server certificate is withdrawn by a serial in `mgmt_peer_denied`,
   which is read at boot and takes effect when the gateway next restarts (the restart disconnects the
   agents on that node; see the gateway manual for the conditions). CRL-fed withdrawal is PR 4b: a
   gateway that sets `mgmt_crl_source` refuses a withdrawn certificate on the streams it admits after
   its next fetch (within one refresh interval of the server publishing), with no restart, even on a
   connection the server already holds open; a stream already running is not cut. After a CA re-root, the source must serve the
   new CA's CRL, or unset it: a CRL signed by the old CA no longer verifies against a new
   `cacertfile` that holds only the new root, so the gateway refuses every stream as
   `revocation_unknown` until it does. In a bundle that holds both roots (which share a subject name
   after a same-host re-root) the old root's CRL verifies, but it covers only peers the old key
   issued: a peer of the new root gets `revocation_unknown` from it, because the loaded CRL is bound
   to the keys that signed it and not to a name. The gateway also loads only a CA's complete base
   CRL (a delta, scoped or indirect CRL, or one with an unprocessable critical extension, is refused
   `malformed`; ADR 2004 "What counts as a complete list"); a CA that publishes deltas alongside
   its base CRL has those deltas ignored, which is a residual of using such a CA with this control. A
   gateway with no source still needs the pinned file replaced (within one interval) or the
   deny-list edited (at a gateway restart); an operator who needs fast withdrawal without a CRL
   source can keep a pin in `identity` mode and replace the pinned file.
3. **The deny-list names serials, not keys.** A compromised server **key** is withdrawn by denying
   every serial issued over it (the server's `superseded` re-issue means there may be two), or by
   re-keying the set. The server refuses to re-certify a key it has seen revoked for any other reason
   (see `docs/pki-architecture.md`).
4. **The derivation trusts the `cacertfile` the listener already trusts.** Whoever can replace that
   file already controls which certificates the listener accepts at all; the derivation adds no new
   write path. A CA bundle derives nothing and needs an explicit `mgmt_peer_identity`.
5. **Operator-supplied certificates (`--cert`/`--key`)** never carry the identity and stay on
   pins. A mixed fleet of gateways is configured per gateway.
6. **A rolling server upgrade, and what gates the move to `identity`.** A replica still on an older
   binary presents a certificate without the URI until it restarts; `identity_or_pin` admits it by its
   pin. The move to `identity` needs **both** conditions, and neither is sufficient alone.
   `yuzu_server_identity_uri_present` reading 1 is set once at server boot and describes the file
   `default-server.pem`: it does not see the certificate the server presents to the gateway (a server
   given its own `--cert`/`--key` presents that one, even while default certificates stay active
   for another listener and the gauge still reads 1), and a
   replica on the previous binary does not export it. `yuzu_gw_mgmt_auth_admitted_total{method="pin"}`
   standing still proves nothing on an idle gateway, so real command traffic must first go through the
   gateway, with `{method="identity"}` moving and `{method="pin"}` not.
7. **The identity trusts the CA's issuance policy.** See the threat model: a bring-your-own corporate CA
   that lets a requester choose a URI SAN with serverAuth, or any CA in a bundle, can mint the identity.
   The install CA is the only issuer this change can vouch for. A bundle is refused at boot unless
   `identity` mode with a pin; a single-certificate corporate CA cannot be detected, so the
   identity must not be enabled there (stay in `pin`).
8. **Reason reporting in the transition mode.** In `identity_or_pin` with pins configured, when both
   paths fail the pin's reason (`pin_mismatch` / `no_pins_resolved`) is reported for a peer without the
   identity, and the identity's (`no_uri_san`, `identity_mismatch`) is not, so those two reach
   `YuzuGatewayMgmtAuthRejected` only when no pin is configured. `identity_unresolved` (the gateway
   could not resolve its identity and the pin does not admit the peer) and `revoked` are reported as
   themselves in every mode. A pin that never resolved is reported
   (`yuzu_gw_mgmt_auth_pin_unresolved_total`, `YuzuGatewayMgmtPinUnresolved`) even while the identity
   admits the traffic.
9. **Server-side residuals that bear on the deny-list.** #6068: a crash or an unconfirmed revoke during
   the identity upgrade can leave an active `ca_issued` row for the same key that nothing ever revokes,
   which matters when withdrawing by "every serial issued over the key". #6070: the upgrade checks the
   bootstrap-lock connection once, before it records the new certificate, so a replica that loses the
   lock mid-upgrade can leave an extra active row. #6069 (related, multi-replica rollout): a new-binary
   replica racing an old-binary one on a first boot of a shared `--ca-dir` can time out and refuse to
   boot. All three are open.
10. **Gateway rollback.** A gateway binary from before #6016 ignores `mgmt_peer_auth_mode`,
   `mgmt_peer_identity` and `mgmt_peer_denied` (they are per-key `application:get_env` reads that
   nothing else makes). After a rollback the deny-list is not honoured: a withdrawn serial whose key is
   still in a pin is admitted again, with no signal. If the node has no pins (dropped for `identity`, or `identity_or_pin` on the
   identity alone), the older binary refuses to boot (`no_mgmt_peer_pins`) and the command plane for that node is down. The
   rollback is itself a gateway restart, which disconnects the node's agents; do it only if they can
   take the disconnect, because agents without the #5183 fix stay wedged after it. Mitigation is procedural:
   restore the pins and re-check withdrawn serials against the CA inventory before rolling back
   (`docs/user-manual/gateway.md`, "Rolling back"). The statement that rolling back is safe because an
   older build ignores the extra URI is about the server certificate only.
11. **A CA re-root in identity mode.** During a re-root the management listener's `cacertfile` may
   legitimately hold the old and the new CA (a bundle). A derived identity is then unresolved, and
   `identity_over_ca_bundle` blocks an explicit one unless the mode is `identity` and a pin is
   configured. A gateway restart in that window with mode `identity` and no explicit identity plus pin
   refuses to boot. Stay in, or return to, `pin` for the duration, or set the explicit identity of the
   new CA with mode `identity` and a pin; afterwards update the explicit identity (a stale one is
   flagged by the boot warning that it differs from the derived one). See `docs/pki-architecture.md`,
   "Deliberate clean re-root".
12. **A serial typed wrongly is a silent narrowing.** The deny-list takes the full hex serial. A serial
   copied from the dashboard CA table is truncated to 16 characters plus an ellipsis; a decimal serial
   is read as hex. Neither is a boot error when it is still valid hex. The boot logs the list as the
   upper-case hex it parsed to, and the operator guide says to take the serial from
   `openssl x509 -serial` or the `serial_hex` field of `GET /api/v1/ca/issued`. Listing the serial of
   the certificate the server currently presents refuses every command (`revoked`), and the server does
   not retry. The gateway keeps no record of who changed the list; `sys.config` should be under version
   control.
13. **Unchanged limits of the listener**: the log line is rate-limited per reason and names no
   certificate contents; any holder of an install-CA certificate that reaches the port can provoke a
   counted rejection per stream. Admissions are aggregate only: the `admitted` counter carries the
   method and nothing else, so there is no per-peer or per-serial admission trail on the gateway
   (the audit trail of what the server then commanded is the server's audit log).

## Amendment (release N+1, 2026-10-19): the shipped configs set the identity

Release N shipped the identity as an opt-in. The accepted trust regression above (a holder of the
install CA key alone can command the fleet in the identity modes; withdrawal needs a serial and a
gateway restart) was accepted for the opt-in. Setting it in the shipped configs extends it to every installation
that takes the new reference config, so this amendment records what changed and what did not.

| Change | Effect on the analysis |
|---|---|
| Reference configs set `identity`, no pin | The trust regression above is now the default posture for a fresh or re-copied config; an operator who needs a pin to be what admits must set `pin` or keep a pin under `identity` (it must then also match). |
| Unset mode stays `pin` | The unset-mode trap (a missing key silently turning on a derived identity) is not reopened, and release N's published promise (an unset value is always `pin`, so nothing changes until the operator sets it) is kept: an installation with its own config is unaffected, a configuration with no pins and no mode still refuses to boot on an exposed listener, and the boot logs a WARN that the mode was defaulted to `pin`. A later release may make the identity the default for an unset key. |
| `pin` and `identity_or_pin` remain | Certificates that carry no identity (bring-your-own, `--no-default-certs`, a server given its own `--cert`/`--key`) have no other way to be admitted. Removing `pin` was rejected. |
| Bundle guard unchanged | An explicit identity over a `cacertfile` that is not demonstrably one certificate still needs mode `identity` with a pin, whatever way the mode was chosen. |

New residual risk, accepted here: an own-certificate installation that takes the new reference config
without setting `pin` loses its command plane (every command refused `no_uri_san`, alert
`YuzuGatewayMgmtAuthRejected`, and the critical `YuzuGatewayMgmtIdentityOutage` once the gateway has admitted
nothing for five minutes). It fails closed and visibly, which is why it was preferred to a
silent fallback, and `docs/user-manual/upgrading.md` states the action before the upgrade. A gateway on
`identity` in front of a server replica that has not re-issued its certificate fails the same way,
so the server is upgraded first.

Gate: the amendment is merged no earlier than a release that mints the identity (#6072) has shipped
and one release has passed since the gateway check (operators also upgrade every server replica
first, an operator action); see ADR 2004, "Merge and release gate". The risk acceptance above (three consequences) is
unchanged in who may give it: the approving reviewer records it (flip ADR 2004 to `accepted`, or
append a `governance.d` row).

### Findings during governance (2026-10-20): two candidate unset-mode defaults rejected

1. **Unset = `identity_or_pin` when pins are listed.** The draft of this amendment used it so a
   pin-only installation would keep working. A reviewer found, and a run with an attacker
   certificate that carried the public identity verified, that it widens trust: the identity
   (`yuzu://<hash-of-CA>/server`) is derived from the public CA certificate, so under a
   bring-your-own or corporate CA that lets a requester choose a URI SAN, any certificate that CA
   issues would have been admitted by a key the operator never set. Rejected.
2. **Unset = `identity`.** The architect review rejected a literal `identity` default for three
   reasons: it contradicts release N's published promise that an unset value is always `pin`; it
   refuses every command of a pin-only install whose server certificate carries no identity (an
   outage cohort); and it makes a pin-only install with a CA bundle on the management listener
   refuse to boot (`identity_over_ca_bundle`). The owner chose unset = `pin` (2026-10-20), with the
   identity carried by the shipped configs and the WARN telling operators the key is unset.

## Follow-up work

- Identity in the shipped configs; pins optional-only (release N+1): done, see the amendment above. Making the identity the default for an UNSET key is not done; a later release may, after the unset-mode WARN has shipped.
- ~~CRL-fed automatic withdrawal with `revocation_stale` / `revocation_unknown` refusals.~~ Delivered in PR 4b (ADR 2004, Amendment A1 to A8).
- The reverse hop (gateway to server) is unchanged; a symmetric identity there is a separate decision.
- #5988 (the server does not retry `UNAUTHENTICATED`) remains and is no longer on the renewal path.

## Where this is enforced

`gateway/apps/yuzu_gw/src/yuzu_gw_authz.erl` (admission order, comparison, deny-list),
`yuzu_gw_mgmt_identity.erl` (modes, derivation, validation), `yuzu_gw_app.erl`
(`check_mgmt_auth_config/0`, `evaluate_mgmt_posture/4`), `yuzu_gw_telemetry.erl` (closed reasons,
admitted counter); server side `server/core/src/default_certs.cpp` (the only minter).
Tests: `yuzu_gw_mgmt_identity_tests`, `yuzu_gw_app_tests`, `yuzu_gw_config_posture_tests`,
`yuzu_gw_real_mgmt_SUITE`, `tests/prometheus/yuzu-alerts.test.yml`.
