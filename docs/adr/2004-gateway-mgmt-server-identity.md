# ADR-2004 — Gateway management plane: authorize the server by a CA-issued identity, not an SPKI pin

---
status: proposed
owner: Fraser Jarvis (@fjarvis)
---

**Authors:** Fraser Jarvis (@fjarvis)
**Date:** 2026-10-18
**Relates to:** #6016 (this change), #1422 (the SPKI pin it refines), #5696 (the pin watcher), #5988
(server does not retry `UNAUTHENTICATED`), ADR-0053 (CA store), `docs/pki-architecture.md`,
`docs/security-reviews/gateway-mgmt-identity-2026-10-18.md` (the security review of this decision)

## Context

The gateway's management listener (`:50063`) carries the server's command fan-out to every agent the
gateway holds. It is the most privileged hop in the product. TLS has already proved the peer holds a
certificate from the install CA, but that CA also signs every agent leaf and the gateway's own leaf
(whose key sits in a group-readable volume under `--cert-group`), so the chain, the serverAuth usage
and the DNS/IP names cannot tell the server from the gateway. #1422 closed that by pinning the
SHA-256 of the server leaf's SubjectPublicKeyInfo (`mgmt_peer_pins`).

The pin works and has a real cost. It binds authorization to a **key**, and the server's key is
renewable: a renewal with a new key is refused until every gateway's pin file reads the new
certificate (`pin_mismatch`), the server does not retry that refusal (#5988) so the commands in the
window fail, and an operator manages pin files per gateway. #5696 shortened the window to one refresh
interval; it did not remove it.

PR #6072 (the first half of #6016) made the install CA mint a **server-only URI SAN**,
`yuzu://<install>/server`, onto the `default-server` leaf, and nothing else. `<install>` is the
upper-case SHA-256 of the CA certificate with the colons stripped, the same value the agent URI family
`yuzu://<install>/agent/<id>` already uses. `sign_agent_csr` ignores a CSR's SAN and only ever emits
the agent URI, and the gateway's leaf carries no URI, so neither an agent nor the gateway can obtain
it. A lexical gate (`tests/test_server_identity_uri_lexical.py`) pins who may mint it. That change
was inert for the gateway; this decision is the gateway side.

## Decision

### 1. Admit the server by its identity

`yuzu_gw_authz:check_mgmt_peer/1` admits a peer that is CA-verified (by TLS), carries the serverAuth
usage, and has the expected identity among its URI SANs. Check order: decode, serverAuth, mode
(identity and/or pin), deny-list. The comparison is **byte equality** against the resolved
identity, on any one URI SAN of the leaf: no case folding, no URI normalisation, no prefix match
(an agent URI shares the `yuzu://<install>/` prefix), and a SAN that is not Latin-1 simply cannot
equal it. A server key renewal that keeps the identity needs no change on the gateway when no pin is
configured, or in `identity_or_pin` (where the identity admits the renewed key whatever the pin says);
in `identity` mode a configured pin must also match, so it must follow the renewal. In
`identity_or_pin` with pins configured, when both paths fail the **pin's** refusal reason
(`pin_mismatch` or `no_pins_resolved`) is the one reported for `no_uri_san` and `identity_mismatch`,
so the existing pin alerting keeps its meaning through the transition. `identity_unresolved` is the
exception: when the gateway could not resolve its identity and the pin does not admit the peer, the
reason reported is `identity_unresolved`, because that is a gateway configuration defect and not a
rotation. `revoked` is always reported as itself. With no pin configured the identity's own reason
is reported. In `identity_or_pin` a pin that never resolved (a typo'd fingerprint, an unreadable pin
file) is reported (`yuzu_gw_mgmt_auth_pin_unresolved_total`) even while the identity is admitting
the traffic, so a dead fallback does not go unseen until the day it is needed.

### 2. Three modes, selected explicitly

`{yuzu_gw, mgmt_peer_auth_mode}`:

| Mode | Admits | Selected when |
|---|---|---|
| `pin` | an SPKI pin (`mgmt_peer_pins`), as before #6016 | the key is unset (always), or set to `pin` |
| `identity_or_pin` | the identity **or** a pin | only when an operator sets it |
| `identity` | the identity, **and** any pin that is configured | only when an operator sets it |

An unset `mgmt_peer_auth_mode` is **always** `pin`. The identity is an explicit opt-in and is never
implied by a missing key, so a configuration with no pins and no mode still refuses to boot on an
exposed listener (`no_mgmt_peer_pins`), exactly as before #6016. An installation that does nothing
keeps its pin behaviour across the upgrade, and the shipped reference configs
(`gateway/config/sys.config.prod`, `deploy/docker/reference-gateway-sys.config`) ship
`{mgmt_peer_auth_mode, pin}` explicitly. If `mgmt_peer_identity` is set while the mode is `pin`, the
identity is ignored and the boot logs a warning saying so. Bring-your-own certificates,
`--no-default-certs` and a server given its own `--cert`/`--key` never carry
the identity and stay in `pin`.

### 3. The identity is resolved once, at boot

`{yuzu_gw, mgmt_peer_identity}` states it. Otherwise it is **derived** from each management
listener's `cacertfile`, and **only if that file holds exactly one certificate**
(`yuzu://` + upper-case hex SHA-256 of its DER + `/server`). A CA bundle, an empty, unreadable or half-written file or an
absent one derives nothing: the identity is unresolved and every peer that needs it is refused
(`identity_unresolved`); an exposed listener refuses to boot when nothing can admit the server (no pin in
`pin`, no resolved identity in `identity`, neither in `identity_or_pin`). Two management listeners that derive different values refuse the boot. The result is
published to `persistent_term`, so the per-stream check does no I/O (the #5696 rule).

An identity is only as strong as the issuing CA's refusal to mint it for anyone else. That holds for
the Yuzu install CA, which mints it only onto the `default-server` leaf. It does not hold for every CA
in a **bundle**: any CA in a management listener's `cacertfile` could mint it. So an identity that
resolved (an explicit `mgmt_peer_identity`; a bundle derives nothing) over a `cacertfile` that is not
demonstrably exactly **one** readable certificate refuses the boot (`identity_over_ca_bundle`),
unless the mode is `identity` **and** at least one pin is configured. "Not demonstrably one" covers
more than one certificate and also an empty, unreadable or half-written file: the listener reads the
file again when it starts, so a guard that passed on a file it could not read at that moment could
be raced by whatever the listener then finds. A plaintext listener with no `cacertfile` is not
judged. Then the pin must also match, so a holder of another bundle
CA's key, who does not have the server key, is still refused. The identity trusts the issuing CA's
issuance policy: a bring-your-own single-certificate corporate CA that lets a requester choose a URI
SAN with serverAuth would let that requester mint the identity, so the identity must not be enabled
there (stay in `pin`; a pin is immune to this).

### 4. Withdrawal is by serial number

With a pin, withdrawing a server certificate meant replacing the pinned file. An identity does not
withdraw itself: once a leaf carries `/server`, removing a pin no longer removes it. So the
mode ships with a deny-list, `{mgmt_peer_denied, [{serial, "0A1B2C"}]}` inside the `{yuzu_gw, [...]}`
list of `sys.config` (1 to 40 hex digits per serial, any case, at most 4096 entries), applied to every
admission path in every mode (reason `revoked`). It is keyed on the **serial, never the key**: the
server re-issues its leaf **over the same key** to add the identity, and revokes the old serial as
`superseded`, so a key-keyed entry would also refuse the replacement. A malformed entry refuses
the boot. The list is read at boot; a change takes effect when the gateway next restarts (which
disconnects the agents on that node; see `docs/user-manual/gateway.md`). Applying revocations
automatically is the CRL-fed follow-up below.

### 5. Rollout

- **This change (release N).** The gateway understands all three modes and the deny-list; the
  reference configs stay on `pin` and nothing changes for any installation until an operator opts in
  (the runbook in `docs/user-manual/gateway.md`, "Authorizing the server by its identity": set
  `identity_or_pin`, keeping the pin). The operator moves on to `identity` only when **both** of these hold, and
  neither is sufficient alone. (1) The server's `yuzu_server_identity_uri_present` gauge reads `1`
  on every replica (alert `YuzuServerIdentityUriAbsent`); the gauge is set once at server boot and
  describes the file `default-server.pem`, so it does not see a server given its own
  `--cert`/`--key` (that certificate is what the gateway receives, even while default certificates stay
  active for another listener and the gauge reads 1), and a replica still on the
  older binary does not export it. (2) After real command traffic has gone through the gateway,
  `yuzu_gw_mgmt_auth_admitted_total{method="identity"}` moves and `{method="pin"}` does not;
  `{method="pin"}` standing still on an idle gateway proves nothing.
- **Rolling back.** A gateway binary from before #6016 ignores `mgmt_peer_auth_mode`,
  `mgmt_peer_identity` and `mgmt_peer_denied` (nothing else reads those keys). After a rollback the
  deny-list is not honoured, so a withdrawn serial whose key is still in a pin is admitted again,
  with no signal; and a configuration with no pins (dropped for `identity`, or `identity_or_pin` running on the
  identity alone) makes the old binary refuse to boot (`no_mgmt_peer_pins`) and takes the command plane down. The rollback is
  itself a gateway restart. Restore the pins first (`docs/user-manual/gateway.md`, "Authorizing
  the server by its identity", "Rolling back").
- **Release N+1.** Pins become an optional extra constraint only; `pin_mismatch` rotation alerting is
  retired for identity-mode installations. Gated on every server replica having run a release that
  mints the identity (a replica on an older binary keeps a URI-less certificate until it restarts).
- **Follow-up (same issue).** CRL-fed automatic withdrawal: the gateway reads the CA's CRL,
  verifies it against the CA, and refuses `revocation_stale` / `revocation_unknown` rather than
  admitting on a missing list.

## Alternatives considered

| Alternative | Why not |
|---|---|
| Keep pins, push the new pin to every gateway on rotation | Needs a trusted control channel to the gateways, which is the thing being authorized. |
| Authorize on subject CN | `agent_id` is chosen by the endpoint and lands in the leaf CN verbatim; an agent can mint a CA-issued leaf with any CN, the server's included. |
| A `dNSName` SAN | DNS names are what hostname verification already uses and the gateway leaf shares them; a URI SAN is not a name any client dials. |
| A separate server-only issuing CA | Strongest separation, but a second CA to generate, store, rotate and publish for every installation, to protect one hop. |
| Short-lived server leaves (cheap revocation) | The server never renews its leaf and the client credentials have no hot reload; large, and still needs the identity. |
| OTP `crl_check` on the listener | The listener refuses ssl keys outside its closed key set; a handshake-only check on one long-lived management connection is weaker than the per-stream `auth_fun`; a stale list with a non-HTTP distribution point fails with no closed reason. |
| Admit when no CRL has been fetched, and alarm | An attacker can force "never fetched" on every gateway start. It violates the fail-closed rule of the PKI row; **rejected outright**. |

## Consequences

**Trust now rests on the CA key, not the server key.** A pin required the server's *private key*.
The identity requires a certificate the install CA signed with that URI, so whoever holds the CA
key (or can cause the server's signer to mint it) can now command the fleet without the server key.
In the default deployment the CA key and the server key are both `0600` files in the same cert
directory on the server host (the directory is `0700`, or `0750` with `--cert-group`, and of the
private keys only the gateway key is group-readable; the compose gateway container mounts the volume
read-only and cannot read the CA or server key), and a CA-key holder can already mint agent certificates and impersonate the
server to agents, so "server key leaked, CA key intact" is the only narrowed case; a CA-key
compromise is a re-root either way. A deployment that keeps the CA key somewhere the server key is
not (a hardware-backed `KeyProvider`) loses that separation on this hop in `identity` and
`identity_or_pin`; it should stay in `pin`, or use `identity` **with** a pin, which requires both.
`docs/security-reviews/gateway-mgmt-identity-2026-10-18.md` records this analysis.

**The identity trusts the issuing CA's issuance policy.** The identity is a claim by the CA that
only the server holds it. For the Yuzu install CA that is enforced in code (`sign_agent_csr` never
emits it). A corporate CA used as the management listener's `cacertfile` may let a requester pick a
URI SAN with serverAuth, and a `cacertfile` bundle holds several CAs, any of which could mint it.
Neither case is detectable from the gateway, so the identity is opt-in, a bundle needs `identity`
mode with a pin (`identity_over_ca_bundle`), and a single-certificate corporate CA whose issuance
policy is not known to refuse the URI stays in `pin`.

**Interim loss of automatic withdrawal.** A `cert_file` pin was withdrawn by replacing a file within
one refresh interval. An identity is withdrawn by a serial in `mgmt_peer_denied` plus a gateway
restart, until the CRL-fed follow-up lands. This is a regression in the speed of withdrawal for the
installations that move to `identity`, accepted for the gain of key renewal with no gateway
action. Two server-side follow-ups bear on "deny every serial issued over the key", so on how
complete a deny-list can be today: #6068 (a crash or an unconfirmed revoke during the identity
upgrade can leave an active `ca_issued` row for the same key that nothing ever revokes) and #6070
(the upgrade checks the bootstrap-lock connection once, before it stages and records the new
certificate, so a replica that loses the lock mid-upgrade can race a sibling and leave an extra
active row). #6069 is the related multi-replica rollout case: a new-binary replica racing an
old-binary one on a first boot of a shared `--ca-dir` can time out and refuse to boot.

**Fail-closed throughout.** Unresolved identity, undecodable certificate, unreadable serial of an
otherwise admitted peer when a deny-list is configured, malformed deny entry (including an improper
list): each refuses. New closed rejection reasons:
`no_uri_san`, `identity_mismatch`, `identity_unresolved`, `revoked`; `revoked` and
`identity_unresolved` are always reported as themselves, while `no_uri_san` and `identity_mismatch`
are reported as the pin's reason in `identity_or_pin` when pins are configured. New counter
`yuzu_gw_mgmt_auth_admitted_total{method="identity"|"pin"}`; new server alert
`YuzuServerIdentityUriAbsent`; the pin alerts are unchanged.

**Rolling back is not free.** The extra keys are per-key `application:get_env` reads that a
pre-#6016 gateway never makes, so an older binary silently drops the deny-list and, if pins were
removed for `identity` mode, refuses to boot. Restore the pins before rolling back. The rule that a
configured name is harmless to an older binary holds for the server certificate (`docs/pki-architecture.md`),
not for the gateway.

**Risk acceptance.** Two consequences above are accepted risks: a CA-key-only holder can command the
fleet in the identity modes, and automatic withdrawal is lost until the CRL-fed follow-up lands. The
author does not approve their own risk acceptance. The acceptance is recorded by the approving
reviewer on the pull request, with a review-by date set there. To make it durable in git, the
approving commit flips this ADR's status to `accepted` or appends a `governance.d` row naming the
approver, the date and the review-by date; this ADR carries neither a name nor a date for it.

**Review record.** The governance run for this change is the committed ledger
`governance.d/6016-gateway-mgmt-identity.*.jsonl` (the random suffix is generated at commit time).
The design review by the `enterprise-architect` validator is not retained as an artifact; its
required changes are folded into the design recorded here.

**Out of scope.** The reverse hop (gateway to server, the gateway-upstream peer authorization) keeps
its pin; a symmetric identity there is a separate decision.
