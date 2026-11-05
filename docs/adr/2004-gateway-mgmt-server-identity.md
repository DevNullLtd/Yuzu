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
| `pin` | an SPKI pin (`mgmt_peer_pins`), as before #6016 | the key is unset (always), or set to `pin`: required for certificates that carry no identity |
| `identity_or_pin` | the identity **or** a pin | only when an operator sets it (the explicit transition mode) |
| `identity` | the identity, **and** any pin that is configured | only when an operator sets it (release N+1: both shipped configs do) |

**Release N and release N+1.** An unset `mgmt_peer_auth_mode` is **always** `pin`, in release N and
in release N+1. The identity is never implied by a missing key, so an installation whose own
`sys.config` does not set the key keeps its pin behaviour across the upgrade, and a configuration
with no pins and no mode still refuses to boot on an exposed listener (`no_mgmt_peer_pins`),
exactly as before #6016. The boot logs a WARN that the mode was defaulted to `pin`. What release
N+1 changes is the shipped reference configs:

- the reference configs (`gateway/config/sys.config.prod`,
  `deploy/docker/reference-gateway-sys.config`) set `{mgmt_peer_auth_mode, identity}` and list **no
  pin**, so a server key renewal needs no gateway action. A pin there would also have to match and
  would re-create the renewal window;
- `pin` stays, as the explicit mode that bring-your-own certificates, `--no-default-certs` and a
  server given its own `--cert`/`--key` must set. Removing it was rejected: those installs cannot
  carry the URI and would have no way to admit the server. An own-certificate install that takes
  or copies the new shipped config without setting `pin` is refused `no_uri_san` (counter
  `yuzu_gw_mgmt_auth_rejected_total{reason="no_uri_san"}`, alert `YuzuGatewayMgmtAuthRejected`, and the critical
  `YuzuGatewayMgmtIdentityOutage` once the gateway has admitted nothing for five minutes);
- if `mgmt_peer_identity` is set while the mode is `pin`, the identity is ignored and the boot logs
  a warning saying so;
- the bundle guard is unchanged (an explicit identity over a `cacertfile` that is not demonstrably
  one certificate needs mode `identity` with a pin).

**Decision and the alternatives.** Chosen: an unset mode stays `pin`, and the shipped configs carry
the identity. Rejected: an unset mode that is `identity`. It refuses every command of a pin-only
install whose server certificate has no identity (an outage cohort at the gateway upgrade), makes a
pin-only install with a CA bundle on the management listener refuse to boot, and contradicts release
N's published promise that an unset value is always `pin`, so nothing changes until the operator
sets it. Also rejected: an unset mode that is `identity_or_pin` when pins are listed, so that a
pin-only installation keeps working untouched. It widens trust without the operator asking: the
identity is derived from the public CA certificate, so under a bring-your-own or corporate CA that
lets a requester choose a URI SAN, any certificate that CA issues carrying that identity would be
admitted by a key the operator never set (a security review verified this by running an attacker
certificate that carried the public identity). A later release may make the identity the default
for an unset key, once the unset-mode WARN has shipped and operators have had time to set the key.

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
automatically is the CRL-fed withdrawal in the amendment below.

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
- **Release N+1 (this amendment).** The shipped reference configs set the identity (see section 2):
  they ship `identity` with no pin, an unset mode stays `pin`, and `pin` is the
  explicit mode for certificates that carry no identity. `pin_mismatch` rotation alerting is not
  deleted: `pin` and `identity_or_pin` remain supported, and an installation on `identity` with no
  pin produces no `pin_mismatch`, so `YuzuGatewayMgmtPinMismatch` stays quiet there by construction.
  Gated on every server replica having run a release that mints the identity (a replica on an older
  binary keeps a URI-less certificate until it restarts): a gateway on `identity` in front of one
  refuses every command.
- **Delivered in PR 4b (see the Amendment, A1 to A8).** CRL-fed automatic withdrawal: the gateway
  reads the CA's CRL, verifies it against the CA, and refuses `revocation_stale` /
  `revocation_unknown` rather than admitting on a missing list.

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
Neither case is detectable from the gateway, so a bundle needs `identity`
mode with a pin (`identity_over_ca_bundle`), and a single-certificate corporate CA whose issuance
policy is not known to refuse the URI stays in `pin`.

**Interim loss of automatic withdrawal.** A `cert_file` pin was withdrawn by replacing a file within
one refresh interval. An identity is withdrawn by a serial in `mgmt_peer_denied` plus a gateway
restart, until the CRL withdrawal of the Amendment (A1 to A8) is configured. This is a regression in the
speed of withdrawal for the installations that move to `identity`, accepted for the gain of key renewal with no gateway
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

**Merge and release gate.** Two conditions, binding on the pull request that makes the shipped
reference configs `identity`:

1. it must not merge until a release that MINTS the identity (the server half, #6072) has shipped;
2. it must not merge until one release has passed since the gateway check (#6131, itself waiting on
   #5695).

Separately, an operator action rather than a condition on the pull request: operators upgrade every
server replica first, before any gateway takes the new config.

**Risk acceptance.** Three consequences are accepted risks: (1) a CA-key-only holder can command the
fleet under the shipped configs (a pin needed the server's private key); (2) withdrawal is a serial
in `mgmt_peer_denied` plus a gateway restart, and revoking the certificate in the CA inventory alone
does nothing. (closed by the CRL amendment below for a gateway that sets `mgmt_crl_source`, and still
open for one that does not); (3) an own-certificate install that takes the
new shipped config loses its command plane (`no_uri_san`) until it sets `pin`. The
author does not approve their own risk acceptance. The acceptance is recorded by the approving
reviewer on the pull request, with a review-by date set there. To make it durable in git, the
approving commit flips this ADR's status to `accepted` or appends a `governance.d` row naming the
approver, the date and the review-by date; this ADR carries neither a name nor a date for it. The
status stays `proposed` until then.

**Review record.** The governance run for this change is the committed ledger
`governance.d/6016-gateway-mgmt-identity.*.jsonl` (the random suffix is generated at commit time).
The design review by the `enterprise-architect` validator is not retained as an artifact; its
required changes are folded into the design recorded here.

**Out of scope.** The reverse hop (gateway to server, the gateway-upstream peer authorization) keeps
its pin; a symmetric identity there is a separate decision.

## Amendment — CRL-fed withdrawal (#6016, PR 4)

Decision 4 left withdrawal as a hand-edited deny-list. The identity makes that worse than the pin:
a pin was withdrawn by replacing a file, and a leaf that carries `/server` is admitted until
something refuses it. The server already revokes a superseded server serial and publishes a CRL on
every revocation (ADR-0053, `CaStore::publish_next_crl`); this amendment makes the gateway read it.
It is delivered in PR 4: 4d (the server CRL's validity and republish cadence, PR #6919) and 4b (the
gateway, this amendment).

### A1. The gateway reads the CA's CRL

`{yuzu_gw, mgmt_crl_source}` is `{url, Url}`, `{url, Url, #{cacertfile => Path}}` or `{file, Path}`.
The gateway fetches the URL (the server's public `GET /api/v1/ca/crl` on 8443) **over verified TLS**,
trusting the management listener's `cacertfile` unless the three-element form names the CA that
issued the server's HTTPS certificate (TLS 1.3 or 1.2 only, with host-name verification; a new connection
per attempt, not one held open). The fetch runs in a bounded worker (3 s a tick, 5 s at boot),
reads at most 16 MiB while streaming, and never leaves the stream path: the watcher publishes the
parsed CRL once per change through `persistent_term`, and the per-stream check does no I/O.
`mgmt_crl_refresh_ms` (default 5000) is the interval and `mgmt_crl_grace_s` (default 86400, at most
604800) the time allowed past `nextUpdate`. Every defect in the setting refuses the boot: `http`,
userinfo, a fragment, an unknown option, a missing or absent fetch CA, an out-of-range value.

A `GetCrl` RPC on the upstream channel was considered and kept as a named fallback only: it adds a
server API surface to solve a reachability problem the shipped topology does not have.

### A2. A CRL is trusted by its signature only

A CRL is accepted only if `public_key:pkix_crl_verify/2` verifies it against a certificate in the
management listener's `cacertfile`. The issuer name and the authority key identifier are hints and
are never the authenticity check. A CRL replaces the held one only when its `thisUpdate` is later or
its `cRLNumber` is higher; an identical CRL is a no-op and an older one is refused (`replay`).
It must also be the issuer's complete base list and is bound to the keys that signed it (see "What
counts as a complete list" and A6(g) below). One
dated more than an hour ahead is refused (`future_dated`). A refused CRL never evicts the loaded
one, so a hostile or broken source cannot evict what the gateway process holds. That holds for the
life of the process: the watcher keeps the mark across its own restart, a gateway process that starts afresh
does not (A6(d)). A CRL that is already past its `nextUpdate` plus the grace is likewise refused
while one still in force is held, because it could only turn every stream into `revocation_stale`.

### A3. Fail closed, per stream, in every mode

After admission and the deny-list, every admitted peer is checked, in `pin` mode too:

| Condition | Reason |
|---|---|
| a source is set and no CRL is loaded | `revocation_unknown` |
| the peer's issuer name is not the CRL's, or the peer certificate does not verify under a key that signed the CRL | `revocation_unknown` |
| now is past `nextUpdate` plus the grace | `revocation_stale` |
| the peer's serial is listed | `crl_revoked` |
| the peer certificate cannot be read | `bad_peer_cert` |

This is the rule the PKI row requires and the one the alternatives table above rejected a
fail-open version of: **there is no "admit and alarm" path**. The closed reason set grows from
eleven to fourteen.

### A4. Cadence, and the renewal rule

The server CRL's validity is 48 hours (it was 7 days) and the server republishes when under 24 hours
remain, so a healthy gateway is never within a day of staleness when the default 24-hour grace
applies: a persistently unreachable server leads to `revocation_stale` about three days after the
last good CRL, with a warning (`YuzuGatewayMgmtCrlStale`) a day earlier. Before 4d the server's CRL
was valid for seven days, so against a server that has not taken 4d the same arithmetic gives about
eight days, and the gateway works against both. The server republishes through its elected leader
(the freshness pass is leader-only), so a period with no leader, or a server that cannot reach the CA
key, stops it; restarting a server replica republishes at startup, whatever its leadership. That
startup publish is load-bearing: a failed one leaves `GET /api/v1/ca/crl` answering 503, and every
gateway then refuses as `revocation_unknown`. The gateway fetches every
5 seconds, so a revocation reaches it within one refresh interval of the server publishing it.

**Renewal rule.** The identity re-issue (the only automatic one) revokes the old server serial as
`superseded` and publishes the CRL at once, so the gateway learns of it within a refresh interval of
the first server replica's restart. A replica that has not restarted yet still presents the old
certificate: in `identity` mode that certificate carries no identity and is refused `no_uri_san`
(unchanged from before this amendment); where a pin admits it (`pin`, `identity_or_pin`) it is refused
`crl_revoked` from the next fetch. Every server replica is therefore restarted back to back, and an
operator does not revoke a server serial by hand while a replica still uses it. A revocation by hand
(any reason but the automatic `superseded`) is not undone by a restart: the server will not re-certify
that key, so the default certificate set is re-keyed (rename `default-marker.json` aside; the server
key and every gateway pin change with it) and every replica restarted. That recovery is in
`docs/user-manual/gateway.md` and the `YuzuGatewayMgmtIdentityOutage` annotation, not only a server log.

### A5. Alerts, and an unset source

`crl_revoked`, `revocation_unknown` and `revocation_stale` raise `YuzuGatewayMgmtAuthRejected`
(warning) and join the `YuzuGatewayMgmtIdentityOutage` selector, so they page (critical) when the
gateway admitted nothing in the same five minutes. Two gauge-driven rules describe the CRL itself:
`YuzuGatewayMgmtCrlNotLoaded` (critical, ten minutes: a source is set and no CRL has verified; the
ten minutes absorb a server that is still starting) and `YuzuGatewayMgmtCrlStale` (warning: past
`nextUpdate`); and `YuzuGatewayMgmtCrlRefreshStalled` (warning: a CRL is held but the source has not
been read successfully for 30 minutes, which is what a wedged watcher or a fetch that keeps failing
looks like while the held CRL is still valid, and which nothing else alerts on for up to 48 hours).
None feeds any readiness probe: an unreachable CRL must not take a gateway out of rotation.

An absent `mgmt_crl_source` under `identity` or `identity_or_pin` logs a WARNING at boot now. **A
later release will refuse to boot there**; that is recorded here as the intent and is not part of
this change. The shipped reference configuration sets the source; `sys.config.prod` carries it as an
example.

### A6. Stated limits

(a) A withdrawal is effective on a gateway after its next successful fetch, up to
`mgmt_crl_refresh_ms` after the server publishes, and only for streams admitted after that: a
management stream already running when the certificate is withdrawn is not cut (a new stream, even on a
connection the server already holds open, is checked and refused). (b) The CRL is signed by the install CA, so a holder of the CA
key can mint a certificate and a CRL that omits it; this is the same trust the identity already
rests on and is not new. Revocation is by serial, not key: a re-issue over the same key is not blocked
by the old serial's entry. (c) A BYO dashboard certificate on 8443 needs the three-element form or a
`{file, Path}` source, and the URL host must be one of its names, or the fetch fails closed. A rollback
to a gateway release that predates `mgmt_crl_source` **silently drops the CRL check**, because that
release ignores the key; the operator is warned only by the absence of the CRL metrics.
(d) **The replace high-water mark is in memory.** The watcher keeps it across its own restart
(the tick state is seeded from the CRL already published), but a gateway process that starts afresh starts
with nothing held and accepts the first validly signed CRL it is given. A source that then serves an
older CRL than the one held before (a restored server database, or a holder of a certificate for the
server's HTTPS name) leaves a withdrawal published after it unenforced until the next CRL arrives, at
most that CRL's `nextUpdate` plus the grace: about three days at the server's 48-hour validity, and
about eight against a server still on the seven-day CRL. This is the recommended option
(seed the watcher, record the residual) and was chosen over bounding the age of a CRL at load, which
would replace the grace semantics the owner set, and over persisting the mark, which needs a writable
path the reference compose does not give; the latter stays a possible opt-in follow-up
(`mgmt_crl_state_file`) if the threat model includes a key holder on the network path who can also
make a gateway start afresh. (e) A CRL grows with every revocation and never shrinks (revoked rows are
append-only), and is refused past 16 MiB (about 470,000 of the server's 36-byte entries, at most about
840,000 of the smallest possible 20-byte ones): every fetch is then `too_large`,
the held CRL is believed until its `nextUpdate` plus the grace, and every stream is refused after
that until the gateway is upgraded; nothing alerts before `YuzuGatewayMgmtCrlStale` except the
size warning logged from 12 MiB (Update of 2026-11-05 below). There is no cap on the entry count
other than that byte bound, and parsing a CRL near it costs about 1.1 GiB (1,111 to 1,153 MiB measured; plan for 1.2 GiB) of transient
memory in the watcher process and 1.9 to 2.5 seconds (measured; see the Update). (f) The fetch
has a fixed 3-second deadline (5 seconds at boot, plus 2 seconds to read the CA files), which is size-blind; a CRL that needs more than
that over the link never refreshes (a persistent `fetch_timeout`). (g) A two-root bundle in the
management listener's `cacertfile` gets `revocation_unknown` for the peers of the root the held CRL
does not cover, and a source that alternates CRLs of two issuers makes that flip tick to tick: the
replace rule compares numbers and times, not issuers. "The root the held CRL covers" is decided by
KEY, not by name: the loaded CRL keeps the public keys of the certificates that verified it, and a
peer is covered only if its certificate verifies under one of them, because serial numbers are
unique only per issuing key and two roots can share a subject name (the server CA's is
`Yuzu Install CA (<hostname>)`, reused by a same-host re-root). A first version compared names only
and so admitted a revoked leaf of the new root while the old root's empty CRL was held (found at
review of PR #7060). A `cacertfile` holding two roots with one subject name is a transition state: do not keep a retired or compromised root in it, because a CRL signed by either key (with otherwise identical content) rebinds the held CRL to that key, and the peers of the other root get `revocation_unknown` until the next CRL. A root whose key is none of RSA, EC or EdDSA (an RSA-PSS key, say)
cannot be bound this way and its CRL is refused `unverified`; an EdDSA root is bound by the curve its
algorithm identifier names. (h) Clocks: a server more than an hour ahead
publishes CRLs the gateway refuses `future_dated` (the held CRL stays); one days behind publishes
CRLs already stale, which the gateway does not let replace a CRL still in force; the new
revocations in such a CRL (a server re-issue among them) then do not land, and the held CRL is
believed until its own `nextUpdate` plus the grace. That trade (a bounded blind window instead of a
fail-closed outage) is the owner's decision recorded in A8, and the gateway logs both CRLs' numbers
and times when it makes it. (i) A `{file, Path}` source or a `cacertfile` on a dead mount or a FIFO blocks the read, and a blocked
file read cannot be cancelled: killing the worker removes the process but leaves its operating-system
thread blocked, and a few of those wedge every file operation in the VM (measured). So a file worker
is never killed: the watcher waits a bounded time, fails the attempt (as `file_unreadable`),
remembers the worker per key in `persistent_term` (so a restarted watcher does not start another)
and starts no new read of that key until the old one returns, which costs one thread, not one per
tick; a read that was merely slow and does finish is adopted by the next attempt. The CRL stops
refreshing meanwhile
(`YuzuGatewayMgmtCrlRefreshStalled`), and the plane stops at `nextUpdate` plus the grace. The CA
reads (the management listener's `cacertfile`, and the fetch CA, which is handed to TLS as
certificates rather than as a path OTP's ssl would read inside the killable HTTP worker) use a raw
file open because `file:read_file/1` goes through the VM's file server process, where
a blocked read stalls every file operation. (The pins watcher still uses `file:read_file/1` for its
own paths: the same hazard, pre-existing and not changed here.) (j) A restored server database (a
lower `cRLNumber` with a fresh `thisUpdate`, and fewer revoked certificates) replaces the held CRL
without any restart, by the owner's replace rule.

**What counts as a complete list.** A CRL is loaded only as the issuer's complete base list of
revoked serials. One carrying `deltaCRLIndicator`, `issuingDistributionPoint` or one of the X.509
scope and ordering extensions (`cRLScope`, `statusReferrals`, `orderedList`, `cRLStreamIdentifier`),
an entry with `certificateIssuer` (an indirect CRL) or a `removeFromCRL` reason, or any extension this
module does not understand that the CA marked critical, is refused `unsupported` (it was `malformed`
until #7070; RFC 5280 5.2 forbids using a CRL with a critical extension one cannot process). A delta with a higher `cRLNumber` would otherwise
replace the full list and drop the serials only the base listed. The Yuzu server publishes none of
these; a corporate CA or a file feed could. Residual: a base CRL from a CA that also publishes deltas
(`freshestCRL`) is accepted as the complete list as of its `thisUpdate`, and the deltas are never
consulted, so a revocation that exists only in a later delta never reaches the gateway. A CA that
publishes deltas should be used with `{file, Path}` fed a freshly built full CRL, or not at all with
this control.

#### Update (2026-11-05): CRL parser and watcher hardening (#7070 items 3 to 6, #7067)

Decided without renumbering A1 to A8; the limits continue after (j).

**(k) Decode before verify (#7070 item 3): a stated limit, no code.** `public_key:pkix_crl_verify/2`
decodes the whole `CertificateList` itself, so the gateway decodes it (to read the fields it needs
and to refuse a policy-unsupported CRL) and the verifier decodes it again; no cheaper pre-check exists,
because a signature cannot be checked until the signed bytes are framed and the framing is most of the
decode. The cost is paid in the watcher process, never on the stream path (the per-stream check reads
`persistent_term`), and once per distinct bytes: a CRL identical to the held one is skipped by its hash,
and refused bytes are remembered (below). Measured for a CRL at the size bound: decode alone 0.24 to
0.6 s, decode plus verify 1.9 to 2.5 s (figures under (l)). A source that serves different junk of that
size on every tick (a holder of a certificate for the server's HTTPS name, or a file feed) still costs
the watcher that much each tick, and so do **identical** bytes that are never remembered: a validly
signed CRL refused `future_dated` or `replay` is decoded and verified in full on every tick for as long
as it is served. A refused body is also downloaded in full on every tick: the memory saves CPU, not
bandwidth, and the server sets no `ETag` on `GET /api/v1/ca/crl`. The byte bound and the watcher's
isolation from the stream path are the only limits on that.

**(l) Revoked-entry count (#7070 item 5): no cap, measured.** The 16 MiB byte bound already limits it:
a DER entry is at least 20 bytes (a 2-byte header, a 1-byte serial as a 3-byte INTEGER, a 15-byte
`UTCTime`), so at most about 840,000 entries; the server's own entries (a 128-bit serial) are 36 bytes,
so about 470,000. A count cap would add a second limit that always sits behind the first, and a CRL a
cap refused would still have been decoded to be counted. OTP has no streaming decoder, so the cost is
stated instead. Measured with `yuzu_gw_crl_build`-style in-memory CRLs on OTP 28.5.0.1, a 32-core Linux
host, `parse/3` run in a fresh process and its memory sampled every millisecond, two runs per shape:

| CRL | Entries | Bytes | Decode only | Decode + verify (`parse/3`) | Peak watcher-process memory | Loaded CRL term |
|---|---|---|---|---|---|---|
| server-shaped (128-bit serials) | 465,916 | 16,773,320 (16.00 MiB) | 243 and 255 ms, 266 MiB | 1,913 and 1,881 ms | 1,153 MiB (both runs) | 23.7 MiB |
| smallest entries (serials 1 to 755,405) | 755,405 | 16,586,359 (15.82 MiB) | 594 and 599 ms, 554 MiB | 2,535 and 2,524 ms | 1,111 MiB (both runs) | 21.2 MiB |

So a gateway that is handed a CRL at the bound needs about 1.1 GiB (1,111 to 1,153 MiB measured; plan for 1.2 GiB) of free memory for the second or two
the watcher parses it (about 2.5 KB per entry at the server's entry size; the earlier figure of "about
half a gibibyte" understated it). Afterwards the loaded CRL is about 21 to 24 MiB per copy, and **two
copies stay resident**: the watcher's state and the `persistent_term` the stream check reads (the parse
result is built on the watcher's heap and then copied into `persistent_term`), so about 45 to 50 MiB.
The watcher collects the parse garbage as soon as the parse returns (a test pins that the heap falls to
a small multiple of the live term). A container limit under the peak kills the VM, not just the
watcher, and the memory shedder (`yuzu_gw_memory_shedder`, which counts `erlang:memory(total)` against
the cgroup limit, high-water mark 0.75 of it by default) suspends the agent listeners during a
near-bound parse on any limit below about 1.6 GiB, before an out-of-memory kill. The jump in the VM's
total memory is the same order as the process figure; the figures are of one idle VM, so a gateway
under load has less headroom, not more.

**The shipped validity bound (#7070 item 4).** New key `mgmt_crl_max_validity_s` (an integer from 3600
to 31536000): the widest `nextUpdate - thisUpdate` a CRL may carry, otherwise refused
`validity_too_long`. It measures the CRL's own two dates against each other and **never against the
gateway's clock**, so a gateway with a wrong clock is not made refuse a good CRL by it (clock faults
stay `future_dated` and the staleness check). The refusal is made after the signature verifies and
before the `future_dated` test: a width is a property of a CRL the CA signed. **Unset in code**, so a
configuration written before this change behaves exactly as before; the **shipped reference
configuration sets 691200 (8 days)**, which must stay above 7 days plus 300 seconds: a server that
predates #6919 publishes CRLs valid for 7 days, backdated 300 seconds, and a gateway upgraded before its
server would otherwise refuse every CRL mid-rollout (A4: the gateway must work against both). A bad value
refuses the boot like its siblings. It closes the "Trust" limit of the manual for a deployment that
sets it: a validly signed CRL with a far-future `nextUpdate` (only the CA key can sign one) is refused
rather than believed until that date. It does not bound a CRL narrower than the setting: the 8-day
default still lets a CRL be believed for up to 8 days plus the grace.

**Two new reasons (#7070 item 6), the closed set is fourteen.** `unsupported` is a CRL that decodes and
is refused by policy (delta, `issuingDistributionPoint`, the X.509 scope extensions, an indirect CRL
or `certificateIssuer` entry, `removeFromCRL`, an unknown critical extension); `malformed` is kept for
what does not decode or is not internally consistent (no `cRLNumber`, `nextUpdate` not after
`thisUpdate`, a serial out of range). The other new reason is `validity_too_long`. They were extended
together in `reject_reasons/0`, the `load_reject()` type, the counter's pre-seed, the metric help
text, `metrics.md`, the Grafana README, `gateway.md`, the alert annotations and the closed-set tests.
The refusal for policy still happens before the signature is checked, so an unsigned delta reads
`unsupported`, not `unverified` (as before it read `malformed`).

**Down-only refresh jitter (#7067 item 2).** Each wait is `mgmt_crl_refresh_ms` shortened by a random
0 to 10 percent, never lengthened: a symmetric jitter would stretch A6(a)'s "up to
`mgmt_crl_refresh_ms` after the server publishes" bound, and down-only keeps it. It desynchronises a
fleet restarted together (precedent: the slowed resend of unacknowledged notices, "jittered down by up to 20%" in the manual).

**Size early warning (#7067 item 3).** A WARN is logged when a fetched body passes 75 percent of the
bound (12 MiB), at most once an hour per watcher process. It is a log line and no gauge, as decided:
the `too_large` counter does not move until the bound is already crossed, which is what the warning is
for.

**Rejected bytes are remembered (#7067 item 4).** After a refusal decided by the bytes and the
verification certificates alone, the watcher keeps the SHA-256 of the bytes and of the certificates
(never the bytes) and does not decode or verify the same pair again until either changes or another CRL
has been accepted. Remembered: `malformed`, `unsupported`, `unverified`, `issuer_mismatch`,
`validity_too_long`, and `too_large` as returned by `parse/4`. **Never remembered:** `future_dated`
(it clears when the clock catches up), **`replay`** (its verdict depends on the CRL held and on that
CRL's staleness: remembering it would turn A8's bounded blind window, where a stale CRL is refused
while the held one is believed, into a `revocation_stale` outage once the held one runs out, because
the same bytes would never be looked at again; a test pins that sequence), and every fetch failure. The
key is the two hashes **and the `max_validity_s` in force**, so a `validity_too_long` memory cannot
outlive a change of the bound. The memory also **lasts one hour** (`memo_ttl_s/0`, measured on the
wall clock the load is given; a clock stepped back past the rejection also ends it): after that the
same bytes are decoded, counted and logged again. That bounds a refusal pinned by a transient fault
(a verification file half-written at the time) and gives a persistently bad CRL an hourly reminder in
the log and on the counter. A
`too_large` found by the fetch (a declared length, a body aborted mid-stream, a file over the bound)
never has bytes to hash, so it is counted every attempt like a fetch failure; in practice the fetch
bound comes first and the remembered `too_large` is a defence in depth.
**A remembered refusal is reported exactly as a fresh one.** `last_success` is the time of the last
attempt that obtained something usable and does not advance on a remembered refusal, and the gauges
carry the same values, so `YuzuGatewayMgmtCrlRefreshStalled` and `YuzuGatewayMgmtCrlNotLoaded` (which
key on the gauges) fire as before; nor is the `ETag` advanced, as for any refusal, so the next request
is not answered 304 and read as success. **Counter semantics change:**
`yuzu_gw_mgmt_crl_rejected_total` counts a remembered refusal once per distinct rejection in a row,
repeated hourly while it persists, not once per tick. No shipped alert rates on it (the three mentions in `yuzu-alerts.yml` are annotation text
that names it as somewhere to read), so no alert changes behaviour; an operator's own rule on its
rate would. The log line, which is emitted when the reason changes, is unchanged.

**Follow-ups recommended (not commitments, none implemented here).**
(i) (#7192) Run `parse/4` in a `spawn_opt` worker with `max_heap_size`, so an oversized parse is a counted
refusal instead of a VM out-of-memory kill. This matters at boot: `init/1` parses synchronously, so an
out-of-memory kill there crash-loops the gateway. A performance reviewer killed a parse with a 512 MiB
limit; the legitimate peak is about 1.1 GiB (1,111 to 1,153 MiB measured; plan for 1.2 GiB), so the `max_heap_size` limit must sit above that (about 1.5
to 2 GiB). It also bounds the hourly re-parse that the memo's one-hour life now allows.
(ii) (#7193) A CRL-size gauge, **absent rather than zero** when no CRL is loaded (`observability-conventions.md`),
and an alert on the gateway job at 50 to 75 percent of the bound, replacing the log-only warning.
(iii) (#7192) A memory-floor note and a `MemoryMax` example in `yuzu-gateway.service` and the compose comments.
Without a floor the failure is a crash loop: under compose (`restart: unless-stopped`) the gateway
restarts and parses again at boot, and under systemd the unit's `StartLimitBurst=3` in 60 s ends it
`failed`, and it stays down. The memory shedder reads the cgroup limit with a default high-water mark of
0.75 (documented in `sys.config.prod`), so a transient parse of about 1.2 GiB suspends the agent
listeners and makes `/readyz` not-ready on any limit below about 1.6 GiB, before any out-of-memory kill;
a `MemoryMax` example therefore needs 1.5 GiB or more of headroom over the shedder's mark.
(iv) (#7066) `ETag` / 304 on `GET /api/v1/ca/crl`, so a refused or unchanged body is not downloaded in full on
every refresh.
(v) (#7193) A "current refusal reason" state gauge: `YuzuGatewayMgmtCrlRefreshStalled` and
`YuzuGatewayMgmtCrlNotLoaded` cannot say which reason persists, and the hourly log line and counter are
the only evidence of it.

**Accepted residuals.** None of the following has been approved by anyone yet; each is recorded here so
that a non-author reviewer can accept or reject it, and none is accepted by being written down.

| Residual | Owner | Review-by trigger | Approver |
|---|---|---|---|
| (a) Transient parse memory about 1.1 GiB (1,111 to 1,153 MiB measured; plan for 1.2 GiB) at the 16 MiB bound, with the boot-time load parsing synchronously | gateway maintainers | a CRL above 50 percent of the bound, any deployment with a container memory limit, or follow-up (i), #7192, landing | approver: unset, a non-author must record it |
| (b) The memo has a single slot: two different bad bodies served alternately are parsed and counted on every tick | gateway maintainers | a report of a feed that alternates bodies, or follow-up (v), #7193, landing | approver: unset, a non-author must record it |
| (c) Identically replayed or `future_dated` validly signed bytes are never remembered and cost the full decode on every tick | gateway maintainers | follow-up (i), #7192, landing, or a server that publishes `future_dated` CRLs in production | approver: unset, a non-author must record it |
| (d) The validity bound is unset in code, so the far-future-`nextUpdate` trust limit stays open for a configuration that does not set it | gateway maintainers | the release that makes the key required, or the boot refusal without a source (#7195) | approver: unset, a non-author must record it |
| (e) The shipped 8-day bound still lets a CRL be believed for up to 8 days plus the 24-hour grace | gateway maintainers | a change in the server's CRL validity, or a shorter shipped default | approver: unset, a non-author must record it |
| (f) A refused body is downloaded in full on every tick (the server sets no `ETag`) | gateway and server maintainers | follow-up (iv), #7066, landing | approver: unset, a non-author must record it |

### A7. Alternatives considered

| Alternative | Why not |
|---|---|
| OTP `crl_check` with `ssl_crl_cache` on the listener | Rejected above for the handshake-only check on one long-lived connection and the closed ssl key set. |
| Trust the CRL on issuer name or authority key identifier | Both are attacker-chosen text; only the signature proves the CA wrote it. |
| Treat a missing or stale CRL as "admit, but alarm" | An attacker can force it; rejected outright, as above. |
| Poll the server's database | No cross-component database access (INV-31-3). |

### A8. Decisions taken at the governance run of PR 4b

The run found that the replace mark was forgotten across a restart and gated on it; the owner
decided on 2026-11-04: seed the watcher and record the residual as A6(d); keep the draft-3 replace
rule (later `thisUpdate` OR higher number) and add only the refusal of an already-stale CRL against
one still in force; keep the server-side CRL `nextUpdate` gauge and alert (#6527) out of 4b, as its
own server change that lands before 4b merges, so 4b's own gauges (which fire only at `nextUpdate`)
do not close that issue. The risk acceptance above is amended only for withdrawal (acceptance 2);
acceptances 1 and 3 stay unrecorded and the amendment does not cover them. The new residuals no
acceptance covers (the fail-closed dependency of a gateway restart on the server and its database
being up, silent loss of the check on rollback, the CRL size cliff, the restart replay window) are for
the approving reviewer to accept or reject; the author does not approve them.

Not run end to end: the reference configuration's live `mgmt_crl_source` has not been exercised against the
real stack (`scripts/integration-test.sh` sets no source and no Common Test case covers the CRL); the
unit, watcher and configuration tests are the evidence, and the first operator on the reference
compose is the first real run.
