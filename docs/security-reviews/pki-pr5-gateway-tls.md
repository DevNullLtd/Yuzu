# Security review — PKI PR5: gateway upstream mTLS + per-agent enrollment through the gateway

- **Date:** 2026-06-04
- **Change:** `feat/pki-pr5` (gateway upstream mutual TLS reference config, `agent_pb`/`gateway_pb`/`management_pb` regen so per-agent enrollment forwards through the gateway, fail-closed-on-unverified startup guard, accurate TLS-posture logging)
- **Reviewers:** Hermes ×2 (adversarial + Anthropic cybersecurity skill-pack); `/governance` Gates 2–6 (security-guardian, docs-writer, gateway-erlang, architect, happy/unhappy/consistency, compliance/sre/enterprise-readiness)
- **SOC 2 controls:** CC6.1, CC6.6, CC6.7 (transmission encryption), CC6.8 (key/crypto management), CC3.2 (risk identification), CC7.2 (change management)
- **Addendum (PR5d, 2026-06-05):** the PR5 regen made the *wire* carry the per-agent cert fields, but `GatewayUpstreamServiceImpl::ProxyRegister` still never signed the CSR — PR5d closes that (signs via the shared `sign_agent_csr` chokepoint; Hermes ×2 + `/governance`, no CRITICAL/HIGH). It also adds a 16 KiB CSR-size cap that **partially closes F-2 below**. The PR5 baseline analysis below is unchanged; PR5b/5c/5d deltas are tracked in the follow-ups + CHANGELOG.

## Scope

The Erlang gateway is an **optional** scale-out command fan-out plane between agents
and the C++ server. This change (a) enables mutual TLS on the gateway→server upstream
hop as a reference config, (b) fixes a silent field-drop so the per-agent enrollment
CSR **survives transit** through the gateway — note this is plumbing only; the gateway
path does **not** sign the forwarded CSR (ProxyRegister has no signer in PR5, so a
gateway-connected agent still gets an empty `issued_certificate` and fails closed to
bootstrap), gateway-path **issuance lands in PR5d** — and (c) makes the gateway's TLS
posture honest + fail-closed.
It does **not** change the agent↔gateway transport (still plaintext — see residual risk
R-1) and does **not** flip the shipped images/composes to TLS-by-default (that is PR5b).

## Threats considered

- **Passive eavesdropping / active MITM on the gateway→server hop.** Mitigated:
  mutual TLS (CA-issued `default-gateway` leaf, `verify_peer`, TLS 1.2 floor,
  ECDHE-ECDSA AEAD/PFS cipher whitelist, depth 2). A real EC mutual-TLS handshake +
  certless-client-rejection are unit-proven. Boot **fails closed** if the channel is
  `https` without `verify_peer` (`evaluate_upstream_posture/2`).
- **Silent downgrade to plaintext.** Mitigated: the latent bug (listener
  `transport_opts` missing grpcbox's required `ssl => true`) is removed; `log_tls_state/0`
  classifies and warns on `unverified`/`plaintext`; the upstream guard refuses boot on
  `unverified`.
- **Confused-deputy via forwarded `csr_pem`.** Not exploitable **in PR5** — but ONLY
  because the gateway path performs no signing yet (B-1). The non-exploitability does
  **not** survive PR5d on its own: once the gateway path signs, the *unauthenticated*
  agent↔gateway hop makes the gateway a confused deputy on the enrollment path. A
  malicious/on-path gateway could (UP-1) swap the agent's CSR for its own keypair — the
  server keys identity off the relayed enrollment token and ignores CSR subject/SAN, so
  it would issue a CA-signed cert for the **victim's `agent_id`** (persistent credential
  forgery); or (UP-2) strip `csr_pem` to silently downgrade the agent to no-mTLS forever.
  **R-6 (hard gate on PR5d):** the gateway must add agent-identity *attestation* — not
  just transport mTLS — before it forwards enrollment. Tracked in
  `docs/pki-architecture.md` deferred follow-ups. In PR5 itself the agent↔gateway hop is
  plaintext (R-1) and signing is absent, so neither UP-1 nor UP-2 was live yet.
  **UPDATE (PR5d):** PR5d shipped the gateway-path signing **without** the attestation
  gate, so UP-1 (CSR-swap identity forgery) is now a **live, bounded, accepted residual**
  — see **R-5** in the register below for the full analysis + compensating controls. The
  gateway is a trusted upstream-authenticated component (see the 2026-10-07 update
  below the register for what that authentication is) and every forged leaf is
  recorded + revocable, which is why this is acceptable for M1 rather than a blocker.
- **Proto field-drop in transit.** Was the live bug (gpb self-contained modules); fixed by
  regenerating all three embedding modules + per-module roundtrip tests. CI codegen-guard
  is follow-up F-3.

## Residual risks (risk register)

| ID | Risk | Likelihood | Impact | Compensating control | Remediation |
|---|---|---|---|---|---|
| **R-1** | **Plaintext agent↔gateway listener (`:50051`).** On an untrusted-network-exposed gateway, an on-path attacker can inject `CommandRequest`s (fleet RCE), read inventory, or impersonate the gateway. No transport auth/confidentiality on that hop. | Med (deployment-dependent) | **Critical** | Deployment-layer: TLS-terminating proxy in front of `:50051`, or keep on a trusted network (VPN/private subnet/mesh). Documented in `gateway.md`, `security-hardening.md`, `sys.config.prod`, CHANGELOG. Direct agent→server is full mTLS. | **PR5c SHIPPED the capability** — a vendored+patched grpcbox (`_checkouts/grpcbox`) enables one-way (server-authenticated) TLS on the agent listener (encrypted + gateway-authenticated, no client cert, bootstrap-safe), turned on in `sys.config.prod`. **R-1 stays OPEN:** the actual *live flip* (compose `--no-tls` removal + shared cert volume + CA-to-agent distribution + the agent fail-closed guard) is **NOT delivered by any merged PR** — PR5b shipped only `--cert-san` + the container cert-dir fix, not the flip. Owned by **#1289**; the deployment-layer mitigation is mandatory until it lands. QUIC (#376) is the longer-term path. |
| **R-2** | **`YUZU_GW_TLS_*` env vars are inert** — they set an advisory `yuzu_gw` env nothing consumes; an operator may believe they enabled TLS. | Low | Med (plaintext upstream by surprise) | `log_tls_state/0` warns unconditionally when the env is set; fail-closed guard catches the resulting `unverified`/plaintext on the upstream. | Env-substituted `sys.config.src` so `YUZU_GW_TLS_*` drive grpcbox cert paths (P1 before any gateway-enabled enterprise deployment guide). |
| **R-3** | **Upstream-TLS failures are not distinctly observable** — expired/wrong-SAN cert / missing volume collapse to a generic circuit-open; an operator can't tell "cert broke" from "server down". | Med | Med (extended incident / MTTR) | Existing circuit-breaker telemetry + `/readyz` 503; startup posture log. | **ADDRESSED:** `yuzu_gw_upstream_tls_handshake_failures_total{rpc_name,kind}` now emitted from `do_rpc` (a depth-bounded `classify_tls_error/1` picks `tls_alert`/bad-ssl-options out of the transport error and labels the cause), distinct from the generic `rpc_error`/circuit-open. Runtime posture gauge is the remaining nice-to-have. |
| **R-4** | **Cert-SAN ↔ dial-name** mismatch silently strands a cross-host gateway (OTP enforces SNI under `verify_peer`). | Med | Med | Documented SAN/`hostname:` requirement in `sys.config.prod` + `pki-architecture.md`. | `--cert-san` flag to add SANs to default certs — **SHIPPED (PR5b)**. |
| **R-5** | **Gateway CSR-swap identity forgery (PR5d signing makes this LIVE — bounded).** Now that `ProxyRegister` signs, a compromised/on-path gateway relays both `agent_id` and `csr_pem`; `X509_REQ_verify` proves only *key*-ownership, not *identity*-ownership, so the gateway can substitute its own keypair's CSR and obtain a **CA-signed leaf for any `agent_id` it relays**. There is **no per-gateway scoping** — any gateway admitted to the upstream service can request a leaf for **any `agent_id` in the fleet**, so a single compromised gateway's blast radius is *universal device impersonation*, not a subset. The forged leaf is valid for **persistent direct (gateway-bypassing) mTLS reconnect** — impersonation that survives gateway eviction. **Scope:** this forges a *device/agent* identity (receive + execute commands as, and report as, that agent, incl. any management-group scope it sits in); an agent is **not** an operator/RBAC principal, so this is device impersonation, **not** operator-role/admin escalation. (Supersedes the "not exploitable" framing in "Threats considered" above, which held only while the gateway was a passive forwarder.) | Low–Med (requires a compromised/on-path gateway) | High (universal per-agent/device impersonation from one compromised gateway) | The gateway is a **trusted, upstream-authenticated** component (not anonymous; see the 2026-10-07 update below for what that authentication is); every forged leaf is recorded in `ca_issued` (inventoried + **revocable**), and once revoked the #1239 HIGH-2 re-issue guard (present in this stack — #1239 merges below PR5d) blocks re-issuance for that `agent_id`; the on-path (non-compromised-gateway) variant is mitigated by PR5c one-way TLS. *(Lineage caveat: the `ca.cert.issued` audit row does not yet carry a `via=gateway_proxy` discriminator — F-4/#1290 — so post-compromise triage must currently scope by other signals; the certs are still fully inventoried + revocable.)* **Accepted residual for M1.** | Gateway agent-identity **attestation** + **per-gateway agent_id scoping** (a gateway may only relay/obtain leaves for agents registered through it) before forwarding enrollment (R-6) — needs through-gateway cryptographic identity (gateway-mTLS / QUIC #376) M1 does not have. Pair revoke with **deny** meanwhile. |

**Update (2026-10-07).** The gateway-upstream service now requires an authorized gateway peer before any request is processed: the caller's TLS-authenticated leaf public key (SPKI SHA-256) must match a pin fixed at server boot, the leaf must carry `serverAuth`, and it must be inside its validity window at the time of the call. The pin is derived automatically only on the server's generated default certificates, and is otherwise explicit (`--gateway-peer-pin`, `--gateway-peer-pin-file`). A plaintext deployment can run only with the explicit `--insecure-gateway-peer` acknowledgement, which disables the check. Withdrawing a gateway key is removing its pin and restarting the server: there is no pin reload and no revocation read on this path. The pin establishes WHICH gateway is calling; it does not restrict which agents that gateway may relay for, so R-5 is unchanged in severity and acceptance: a compromised pinned gateway can still relay another agent's `agent_id`, and per-gateway scoping (R-6) remains the remediation. The phrases above that describe the gateway as upstream-authenticated point at this update; the rest of the review is left as written for the record. Decision record: `docs/security-reviews/gateway-peer-authz-minimal-2026-10-07.md`.

## Tracked follow-ups

- **F-1** — `yuzu_gw_upstream_tls_handshake_failures_total` counter (classify `tls_alert`/`handshake_failure` in `do_rpc`) **— SHIPPED** (R-3); the runtime TLS-posture gauge is the remaining nice-to-have.
- **F-2** — message-size cap (`max_recv_message_length`) on the gateway listener so an oversized `csr_pem`/any field can't pressure memory (pre-existing for all fields). *(PR5d: a 16 KiB CSR-size cap is now enforced at the shared `sign_agent_csr` chokepoint, applying to both the direct and gateway paths — so the `csr_pem` sub-concern is closed. A broader listener-level cap for all other fields remains open.)*
- **F-3** — CI guard: regenerate all gateway `_pb.erl` from the vendored protos + diff against committed, and assert every multi-module-embedded message has an identical `{name,fnum,type}` set matching canonical (would convert R-of-drift into a hard CI failure).
- **F-4** — `via=gateway_proxy` in the server's `ca.cert.issued` audit `detail` when signing arrives via `ProxyRegister` (direct vs proxied issuance traceability). **Filed as #1290** — the forensic lineage for the R-5 residual (scope/triage/bulk-revoke the gateway-issued population after a gateway compromise). Targeted for M1 enterprise-readiness.
- **F-5** — CAIQ/security-questionnaire answer for "is all agent traffic encrypted in transit?" (see "Customer assurance" below).

## Customer assurance (questionnaire answer)

> Agent-to-server connections are protected by mutual TLS (per-agent certificates issued
> by Yuzu's internal CA). When the optional Erlang gateway scale-out plane is deployed,
> the gateway-to-server upstream is also mutual TLS. The gateway agent listener now
> supports server-authenticated (one-way) TLS (PKI PR5c — capability shipped in
> `sys.config.prod` via a vendored patched grpcbox). Distributing the CA to agents
> and flipping the deployed composes to TLS is **not yet shipped** (tracked in
> issue #1289). Until it lands, any internet-exposed gateway deployment must
> protect that hop at the network layer (TLS-terminating proxy or private/VPN
> network). Direct-connect deployments (no gateway) are fully encrypted
> end-to-end.

## Verdict

Net security improvement; **no *uncontrolled* CRITICAL/HIGH**. Two High-impact residuals
are explicitly **accepted with live compensating controls**, not unmanaged: **R-1**
(plaintext agent↔gateway edge — PR5c shipped the one-way-TLS *capability*; the live flip +
CA distribution is owned by **#1289**; deployment-layer mitigation mandatory meanwhile) and
**R-5** (PR5d gateway-path signing makes the confused-deputy CSR-swap forgery live + bounded
— compensated by `ca_issued` inventory + revocation + the #1239 re-issue block + PR5c
one-way TLS for the on-path variant; durable fix is gateway attestation / per-gateway
scoping, R-6 / QUIC #376; lineage follow-up F-4/#1290). Both are acceptable for M1 provided
the network-layer mitigation is enforced for any exposed gateway and gateway revocation is
paired with **deny**. The shipped reference config
+ proto fix are unit-proven (PR5: 194 eunit; PR5c: 200 eunit, dialyzer clean, real EC mutual-
and one-way-TLS handshakes).
