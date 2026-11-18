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
   (bounded per window, with chunked aggregate rows naming the dropped ids, so an attacker looping on one
   id cannot turn the audit store into a disk-fill lever: ~330 B per row at 1000 attempts/s was ~28 GB/day
   unbounded).
4. **Enforce lockout.** An agent that lost its key and has no operator-issued single-use token is
   refused (retrying) until one is issued. A plaintext gateway, or a TLS listener without
   `witness_client_cert`, cannot witness, so under `enforce` its leaf-holding agents are refused
   (`unattested_gateway`, reported before any token is considered).
5. **Multi-use tokens** are refused INSIDE the consume UPDATE (`require_single_use`): the use is not
   counted.
6. **Token-holder takeover (accepted, #8171).** Under `enforce` a holder of an unspent single-use token
   can re-enrol any live-leaf id and supersede its leaf. Recovery is NOT a new token alone (see item 7):
   remove the victim's `cert_dir`, restart it and give it a new single-use token. Token custody is the
   control.
7. **A victim whose certificate file is inside its first two thirds of life sends no CSR; the burnt-token outcome.** The agent sends a CSR only when auto-provisioning and its certificate file is missing, expired or past two thirds of its life (`agents/core/src/agent.cpp`, `CertState`). A direct-TLS agent whose leaf the server revoked (as `reenrolled`, or an operator) is refused at the mTLS gate ("client certificate is revoked") before any token is read; a gateway-relayed one reaches the token block, the single-use token is CONSUMED, no leaf is issued, the call answers `accepted=true` and the agent loops (`yuzu_register_reenrol_token_no_leaf_total{reason="no_csr"}`, alert `YuzuAgentReenrolTokenNoLeaf`). The recovery on BOTH paths is manual: remove the agent's `cert_dir`, restart it, give it a fresh single-use token. A server-side CSR-less refuse-before-consume and an agent-forced CSR are #8252 and #8253 (owner decision 2026-11-18: not in this build; a behavioural pre-consume refusal is the optional alternative).
8. **CRL file latency.** The superseded leaf is refused by the server's mTLS gate immediately; the CRL
   file lags the leader's freshness tick.
9. **No rate limit** on re-registration attempts (#828, out of scope); the new read is one indexed query.
10. **Operator-revoked leaf is irreversible (R12).** The revoked set is append-only and there is no un-revoke action; the revoked-identity guard refuses all issuance for that agent id until the leaf expires (~365 days). If the revoked leaf is an OLD leaf of an id that also holds a newer live leaf, the id still counts as revoked: the agent cannot renew and cannot re-enrol with a token until it expires. Recovery is enrolling under a NEW agent id (the guard is keyed on the exact id); an audited clear-and-reissue route is #8255, review date 2027-03-01.
11. **Audit rows are bounded and can be dropped; the summary is best effort evidence.** Per 10 s window and per server process: 3 rows per repeated id; a reserved bucket (250) for ids not seen recently; per-source (50, at most 1024 sources then one shared `other` bucket) and global (1000) caps for the rest. Dropped rows are counted, and the dropped IDS are written as chunked system-principal aggregate rows (at most 200 ids per row, up to 20000 distinct ids per window, drop order, ids cut to 24 characters, `ids_truncated=N` on every chunk), queued in a bounded 128-row deque and written only by the health thread (every 5 s, 2 s per round) and at shutdown. A dropped id is named in a row only when that flush succeeds: a process kill loses the open window and the queue (47 to 65 percent of recent ids in a kill test). An id no row names (over the 20000 cap, a chunk dropped as queue full, after three failed writes or at shutdown, or a window that could not be built) is counted by id in `yuzu_register_reregistration_audit_ids_truncated_total`, its chunks by cause in `..._audit_summary_dropped_total{reason}`; `..._audit_dropped_total` counts rows. The authoritative count is `yuzu_register_reregistration_total`. Residual (MEDIUM, conditional on this wording and on the alerts `YuzuAgentReregistrationAuditIdsTruncated` and `...AuditSummaryDropped`).
12. **Supersede is best effort (owner decision D4, #8254).** A failure writes `ca.cert.supersede_failed`; a THROW writes no audit row, only a log line and `yuzu_server_ca_supersede_failed_total` (alert `YuzuAgentLeafSupersedeFailed`, manual revoke in the alert runbook). There is no durable "supersede owed" marker, so a crash between issuance and the revoke leaves the older, possibly stolen leaf valid until it expires. `issued_at` has one-second resolution: on a same-second tie whose caller serial is the lower one both leaves stay live until the next re-enrolment (reproduced in PG; never zero). No lock surrounds issuance, only the revoke. Review by 2027-03-01.
13. **Dropped options.** The superseded-leaf carve-out (`1b71bc3686`) and the token-use refund (`65a9339d22`) were reverted by owner decision; the build has neither.

Fix commits: `df2851d309`, `f628b94e60`, `b96ec367b2`, `34a9af4aa0`, `2ac767c28b`, `5cc3865659`, `3a5e49d976`, `2127e95eed`, `6eacba523f`, the Gate 8 pass 3 commits, and the two reverts (see `git log`).
