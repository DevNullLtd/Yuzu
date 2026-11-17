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

## Residual risk (recorded, not accepted silently)

1. **Compromised gateway.** The witnessed certificate is as trustworthy as the gateway (same level as
   `gateway_observed_peer`, R-6 in `pki-pr5-gateway-tls.md`). A pin-authorized gateway can assert any
   certificate. This change closes the unauthenticated-caller hole, not the malicious-gateway one.
2. **Not covered (D7):** `--no-tls`, plain TLS without a client CA, operator-CA-certificate agents, and
   expired leaves are claim-based as before.
3. **Audit-mode window.** Until `enforce` is set the hole is open, by owner decision D3, but visible: every
   would-refuse is counted and logged.
4. **Enforce lockout.** An agent that lost its key and has no operator-issued single-use token is refused
   (retrying) until one is issued. An un-upgraded gateway cannot witness, so under `enforce` its
   leaf-holding agents are refused (`unattested_gateway`): upgrade gateways first.
5. **Multi-use token burn.** A multi-use token presented for a live-leaf id is counted by the store before
   the single-use check can refuse it; the use is not refunded.
6. **Verify-all at the TLS layer.** With `witness_client_cert` the gateway's TLS layer accepts any
   presented certificate chain; the server is the only verifier. A future change that trusts the witnessed
   PEM without `attested_leaf_proves_identity` would be a vulnerability.
7. **No rate limit** on re-registration attempts (#828, out of scope); the new read is one indexed query.
