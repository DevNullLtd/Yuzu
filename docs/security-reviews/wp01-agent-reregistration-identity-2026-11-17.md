# WP01: proof of identity when an enrolled agent re-registers (2026-11-17)

Scope: F1, F3, F5, F22 of the 2026-11-17 Claude Security scan. Basis: `dev` at `5698d858bc`.

## The defect

`AgentServiceImpl::Register` and `GatewayUpstreamServiceImpl::ProxyRegister` each carried a hand-copied
`approved -> goto enrolled` jump keyed on the caller-supplied `info.agent_id`. The mTLS identity check in
`Register` ran only when the caller chose to present a certificate (the default-certificate agent listener
requests but does not require one), so a certificate-less caller of a known id replaced the live registry
session, had the device tokens revoked, and was issued a CA-signed leaf for the victim id. Through the
gateway the listener is `verify_none`, so the server never saw a certificate at all.

## The fix (one decision, two evidence sources)

`agent_reregistration_gate.hpp` (pure decision) and `agent_reregistration_apply.hpp` (lookup, metric, mode,
refusal) are called from both fast paths, before `registry_.register_agent`.

- Trigger: `CaStore::agent_leaf_state(agent_id)`, a LIVE (active, DB-clock unexpired) `purpose='agent'` leaf.
  Expired leaves do not trigger it (owner D2). Revoked-unexpired with nothing live is refused (D5).
- Proof: the current leaf (direct: mTLS peer; gateway: the witnessed leaf), or a fresh single-use token
  (D5: a multi-use token is not proof). Token re-enrolment supersedes the older live leaf after issuing the
  new one (D4, reason `reenrolled`).
- Direct and gateway evidence differ only in where the certificate comes from. The gateway witnesses it
  (`witness_client_cert`: verify_peer, nothing required, no handshake abort on an unchainable certificate)
  and sets `gateway_attested_peer_cert_pem` / `gateway_attests_peer_cert` unconditionally; the direct
  `Register` never reads them. The server verifies the witnessed leaf itself.
- Refusal is a gRPC status (`UNAUTHENTICATED`; `UNAVAILABLE` for a store failure), uniform message, never
  `accepted=false`. Mode `off|audit|enforce`, default `audit` (D3).

## Governance rounds and owner rulings

Fix commits on `fix/wp01-reregistration`: the original fix `df2851d309`; governance round 1
`f628b94e60` (concurrency, missing-row, audit, alerting, docs); the pending-row and audit-budget
follow-up `b96ec367b2`; the alert tests `34a9af4aa0`; and the Gate 8 commits that follow them (see
`git log`). Owner rulings of 2026-11-17: (1) `enforce` REFUSES a re-registration relayed by a gateway
that cannot witness (`unattested_gateway`), fail closed; (2) the spare-single-use-token takeover is the
accepted token-custody residual, tracked as #8171 (an agent-bound token design); (3) `audit` stays
the default and `enforce` is not made the default by this change.

## Residual risk (recorded, not accepted silently)

1. **Compromised gateway.** The witnessed certificate is as trustworthy as the gateway (same level as
   `gateway_observed_peer`, R-6 in `pki-pr5-gateway-tls.md`). A pin-authorized gateway can assert any
   certificate. This closes the unauthenticated-caller hole, not the malicious-gateway one. Key
   possession is NOT delegated to the gateway: the TLS CertificateVerify is checked at the handshake
   even under the accept-any `verify_fun` (empirical test `witness_no_key_possession`: a victim's
   certificate presented without its key is refused with `bad_certificate`).
2. **Not covered (D7):** `--no-tls`, plain TLS without a client CA, operator-CA-certificate agents and
   expired leaves are claim-based (the gate does not apply to them). Wizard, demo and UAT fleets with
   plaintext gateways cannot satisfy `enforce`.
3. **Audit-mode window.** Until `enforce` is set the hole is open, by owner decision D3, but visible:
   every would-refuse is counted, logged, and written as an `agent.reregistration_unproven` audit row
   (bounded per agent id with an aggregate row, so an attacker looping on one id cannot turn the audit
   store into a disk-fill lever: ~330 B per row at 1000 attempts/s was ~28 GB/day unbounded).
4. **Enforce lockout.** An agent that lost its key and has no operator-issued single-use token is
   refused (retrying) until one is issued. A plaintext gateway, or a TLS listener without
   `witness_client_cert`, cannot witness, so under `enforce` its leaf-holding agents are refused
   (`unattested_gateway`, reported before any token is considered).
5. **Multi-use tokens** are refused INSIDE the consume UPDATE (`require_single_use`): the use is not
   counted. (An earlier draft counted it first; fixed.)
6. **Token-holder takeover (accepted, #8171).** Under `enforce` a holder of an unspent single-use token
   can re-enrol any live-leaf id and supersede its leaf; recovery is a new single-use token for the
   victim. Token custody is the control.
7. **Revoked-as-`reenrolled` presenter.** A direct-TLS agent whose leaf was superseded keeps presenting it
   and is answered "client certificate is revoked" before any token is read; documented manual
   recovery (delete the agent's certificate and key, restart with a fresh single-use token).
8. **CRL file latency.** The superseded leaf is refused by the server's mTLS gate immediately; the CRL
   file lags the leader's freshness tick.
9. **No rate limit** on re-registration attempts (#828, out of scope); the new read is one indexed query.
