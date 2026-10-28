# ADR-0074: Gateway transport security and topology: mutual TLS on every hop, SPIFFE identities, many gateways, many servers

- **Status:** Proposed. The owner's decisions below were taken on 2026-10-28; the design details flagged "to ratify" need the owner's sign-off at the end of wave 0.
- **Date:** 2026-10-28
- **Authors:** Nathan Dornbrook
- **Supersedes:** nothing. Amends ADR-2002 (see its section 7h, added with this ADR).
- **Related:**
  - ADR-0069 (the owned gRPC layer over Cowboy and gun, and the overload model), ADR-0066 (gRPC is the permanent transport).
  - ADR-2002 (high availability), ADR-0053 (the CA store on Postgres), ADR-0010 (secrets; the CA key stays behind `KeyProvider`).
  - ADR-0073 (draft: liveness-only heartbeat over a stateless gateway relay). It goes to PR after this ADR is ratified.
  - `docs/pki-architecture.md` (the current trust model and the per-hop TLS table).
  - Issues: #6016 (server identity by URI SAN, open), #5647 to #5651 (several upstream servers, open), #5649 (the reconcile decision, open), #4669 (agent-to-cluster affinity, closed).

## Context

### What runs today

| Hop | Today | Gap |
|---|---|---|
| Agent to server, direct | Mutual TLS. The agent presents its CA-issued leaf (`yuzu://<ca-fingerprint>/agent/<id>`, about a year, renewed at two thirds). One port asks for a certificate but does not require one, so an unenrolled agent can bootstrap; the application enforces the rest. | Only single-server installs use it. ADR-2002 section 2 makes the gateway mandatory in HA. |
| Agent to gateway (`:50051`) | One-way TLS (PKI PR5c). The gateway proves itself; it does not check the agent's certificate. The agent proves itself with its enrollment token, and heartbeats are bound to its Subscribe connection. | No transport identity for the agent at the edge that will face the internet. |
| Gateway to server (`:50055`) | Mutual TLS. The server admits the gateway by an SPKI pin fixed at boot. | Pins are per pair and do not scale to many gateways and many servers. No revocation. |
| Server to gateway management (`:50063`) | Strict mutual TLS. SPKI pin, or (opt-in, #6016) the server's URI SAN `yuzu://<ca-fingerprint>/server`. | No revocation. Pins again. |

So gateway and server already authenticate each other in both directions. The missing link is the agent at the gateway.

### Why it matters now

- **Scale.** ADR-0069 sets 1.2 million agents and 100,000 per gateway.
- **SaaS.** Gateways will face the internet. A compromised or impersonated gateway must not be able to act as an agent.
- **Customers' PKI.** Most target customers already deploy a machine identity certificate (on Windows, in the certificate store behind CNG, often non-exportable or in the TPM). The direction of travel is SPIFFE/SPIRE for workload identity and RATS for attestation.
- **Topology.** The product needs agents that know several gateways, gateways that can be drained for maintenance, and gateways that use several servers writing to replicated Postgres (ADR-2002 section 7g).

### Measurements behind the transport choice (rocky9, 2026-10-28)

These come from branch `perf/gateway-idle-mem-ktls` (a kTLS handover NIF) and are recorded in the private gateway wiki.

| Measure | OTP `ssl` | kTLS NIF |
|---|---|---|
| OS anonymous memory per idle agent (100 Windows agents, TLS 1.2) | 85.0 KB | 48.1 KB |
| Processes per agent | 6 | 3 |
| Handshakes per second, 4 cores | about 2,500 to 3,000 | about 6,000 to 6,600 |
| Memory per connection during a 30,000-handshake storm | 34.3 KiB | 8.4 KiB |
| Memory left after the storm, automatic reclaim | about +30 MiB | about +17 MiB |

The kTLS NIF was fuzzed for 91.2 million executions (92% line coverage, one bug found and fixed) and ran clean under ASan inside the BEAM. It can verify no peer certificate today.

## Decision

### D1. Gateway and server: CA trust, then identity, then revocation

All three, in this order:

1. **Trust our CA, not per-pair pins.** Gateways and servers admit each other by a certificate chaining to the install CA (or the customer's intermediate, D4). SPKI pins stay as an optional extra, not the default.
2. **Identity in the certificate.** Every certificate carries a URI SAN that names the role and the instance (D3). Each side checks the role it expects: a gateway is not a server, and an agent is neither.
3. **Revocation.** Every hop checks the revocation list (D7).

### D2. The agent edge: a separate enrollment port, and a strict main port

- **Main port.** It requires a valid client certificate at the TLS layer. A connection without one never reaches application code.
- **Enrollment port.** It accepts connections without a certificate, and the only thing it serves is enrollment. It has its own rate limit and connection cap at all times.
- **Clean break.** This ships as a breaking change in the next release, with no fallback to the single-port behaviour. There are no customers yet.

### D3. Identities are SPIFFE IDs

The URI SAN takes the SPIFFE form, `spiffe://<trust-domain>/<role>/<name>`. Examples: `spiffe://<trust-domain>/agent/<agent_id>`, `.../gateway/<name>`, `.../server/<name>`.

- The trust domain is derived from the install (to ratify; candidates are the CA fingerprint the `yuzu://` URIs use today, or an operator-set name).
- The existing `yuzu://<ca-fingerprint>/agent/<id>` and `yuzu://<ca-fingerprint>/server` URIs migrate to it. The CA alone chooses the SAN; a requester never does (`sign_agent_csr` already ignores the CSR's subject and SAN).
- A SPIRE server can later replace the issuer without changing what the main port checks.

### D4. Who issues the main-port certificate

- **Yuzu issues it**, always, as a short-lived certificate with a SPIFFE ID (D6).
- **The customer's machine certificate is an enrollment credential only.** On the enrollment port the agent proves it holds the machine certificate by signing a server challenge through the platform key store (Windows CNG, macOS Keychain, Linux file or PKCS#11). That signature is application-layer, so a non-exportable or TPM-held key works. It does not need gRPC to hold the private key.
  - This matters because gRPC 1.76 (the vcpkg pin) takes the client key as PEM and has no public private-key signing hook. So the machine certificate cannot be presented on the main port as it stands.
- **The enrollment token stays a supported credential** for machines without a machine certificate.
- **Customer PKI as the root of trust:** a customer may import an intermediate CA signed by their own root, and Yuzu issues from it. Customer-issued main-port certificates (the customer's CA issuing to agents directly) are not offered at first, and the design must not rule them out.
- **Default:** a customer who brings nothing gets the Yuzu-generated root.
- **Later:** TPM or RATS evidence is added at the enrollment step.

### D5. Agent identity reaches the server end to end

The gateway checks the agent's certificate, but the server does not trust the gateway's word alone. The agent signs a server-issued challenge at the start of every session with its own key. The server verifies the signature against the certificate it issued, and refuses a revoked or mismatched agent.

**Correction, to ratify.** The owner chose this so that a compromised internet-facing gateway can drop or delay traffic but cannot impersonate an agent. A signature at session start proves who opened the session. It does not stop a compromised gateway from forging or altering messages inside that session. That guarantee needs end-to-end message integrity in both directions. Two candidate designs:
- a key agreed per session between agent and server, with a MAC on every message;
- the server signs commands and the agent signs results.

Wave 0 must settle which one (or a scoped subset, such as integrity on commands and results only). The per-session signature alone is the first step, not the whole guarantee.

### D6. Certificate lifetimes and revocation

- **Agent certificates** last 24 hours and are renewed at half-life. At 100,000 agents per gateway that is about 1.2 renewals per second per gateway.
- **Gateway and server certificates** last 7 days, on the same revocation list.
- These replace today's one-year agent leaf and the server and gateway leaves sized to the CA's life.

### D7. Revocation at a gateway that keeps no state of its own

- The gateway pulls the revocation list from the server every 60 seconds and refuses revoked agents at the handshake. That stops a revoked agent before it costs a session, memory and an upstream call.
- It keeps the last good list if a pull fails, and fails closed (refuses new agent handshakes) after 15 minutes without a good pull.
- The server ends a revoked agent's live session immediately.
- The list is the CRL `CaStore::publish_next_crl` already publishes (ADR-2002 section 8). A delta form may be needed at fleet scale; that is to measure, not assume.

### D8. kTLS is the default at the agent edge; OTP `ssl` is the fallback

The reasons are the measurements above, and that this is the model nginx and HAProxy use: OpenSSL's TLS state machine and X.509 code, then kernel record encryption.

Because memory safety is vital, these are requirements, not options:
- a pinned OpenSSL version, with its security advisories tracked and acted on;
- continuous fuzzing of our C code in CI, plus an ASan build exercised by the test suite;
- one shared test suite proving the kTLS and OTP `ssl` paths accept and refuse exactly the same certificates (chain, SAN, EKU, expiry, revocation);
- security review of the C code before it ships enabled.

The difference from nginx is recorded: nginx runs handshakes in worker processes, so a crash costs one worker. Our handshake runs inside the Erlang VM, so a crash costs the gateway. Whether to move handshakes out of the VM later is an open item (see Open questions).

Certificate checking moves into the NIF: `SSL_VERIFY_PEER` with the CA store, the CRL, and the SAN and EKU checks. The current refusal of `ktls` with `verify_peer` goes away.

### D9. Discovery and choosing a gateway

- **"Use DNS" is a design principle.** An agent finds its first gateway by DNS.
- **After first contact,** the server gives the agent the current gateway list, with weights and draining state. The agent caches it on disk for the next start.
- **Choosing:** weighted random choice, with the weight from measured round-trip time, so the nearest gateway in time weighs most and agents do not all pile onto one. Jittered back-off between attempts. Failover down the list.
- **Draining gateways** have weight zero.
- No region or site field in the first version: latency weighting covers it.

### D10. How gateways know about one another

- **Inside a corporate network:** gateways may form an Erlang cluster (the existing `yuzu_gw_cluster_discovery` and hash ring). The cluster's own connections run over TLS (`inet_tls_dist`) with CA-issued certificates. Membership in an Erlang cluster is full control of every member.
- **Outside, including every internet-facing gateway:** gateways never talk to each other. They coordinate only through the server. Erlang clustering is off by default for an internet-facing gateway.
- **Either way,** every gateway reports health, load and draining state to the server, because the server owns the gateway list agents receive (D9).

### D11. Draining a gateway

1. **The order:** an operator issues it through the dashboard, REST API or MCP, RBAC-gated and audited, reaching the gateway through the server (or through the cluster). Automation uses the same API.
2. **What agents receive:** the gateway sets its weight to zero, then sends each agent an HTTP/2 GOAWAY carrying a short suggested list of other gateways. The agent reconnects by its normal weighted choice.
3. **Pace:** GOAWAY goes out in staggered batches over an operator-set window, 10 minutes by default, so no other gateway takes a storm. The gateway exits when empty or at a hard deadline.
4. **Commands in flight:** the agent reconnects elsewhere and delivers the result there. The server must accept a result for a command it sent through a different gateway. The durable command idempotency of ADR-2002 WS-0 and the execution ids carry it.
5. **The enrollment port** stops accepting new connections at the start of the drain window.

### D12. Several servers

1. **All servers active.** Singleton jobs run on the elected leader of ADR-2002 sections 3 and 6.
2. **Each gateway connects to every server** (ADR-2002 section 7g). Each agent's stream goes to one server, chosen by consistent hashing on `agent_id`. When a server is lost or drained, only its agents move.
3. **Reaching an agent:** Postgres records which gateway holds which agent (`agent_routes`). Any server sends a command straight to that gateway's management port. The result returns through the server that owns the agent's stream and lands in Postgres.
4. **Gateways find servers by DNS.**
5. **Draining a server:** it stops taking new agent streams, and its agents are rehashed onto the others in staggered batches.

### D13. Postgres

- **Replication:** one synchronous standby plus any number of asynchronous ones. Writes never fall back to the primary alone (ADR-2002 sections 10 and 13: no acknowledged-write loss while the synchronous quorum holds).
- **Failover:** Yuzu depends on no particular HA tool. It reaches Postgres by one DNS name, or a multi-host DSN, with `target_session_attrs=read-write`. Patroni is the documented on-premises reference; a managed service is the SaaS choice.
- **Targets:** RPO zero for acknowledged writes; write downtime under 60 seconds per failover. While Postgres is unreachable, servers fail closed for writes, as today.
- **Reads:** no reads from standbys in the first version.
- **Leadership** is re-elected after every failover, and every singleton job must tolerate that.

### D14. The gateway budget

This replaces the 8 KiB-per-connection goal set on 2026-10-26.

- **Goal, per box:** one gateway on 8 cores and 16 GB holds 100,000 idle agents with mutual TLS. It must stay inside:
  - memory under 8 GB;
  - idle CPU under 2 cores;
  - a full reconnect of all 100,000 agents within 60 seconds (about 1,700 handshakes per second, plus the D5 signature checks);
  - memory back within 5% of its pre-storm level within 2 minutes.
- **CI regression check, per agent:** 64 KiB per idle agent, all-in including the kernel's per-connection memory.

The memory measures in this ADR's companion change apply to both TLS paths: a garbage collection of the large processes after an agent-count drop, plus a second pass 30 seconds later; a periodic `malloc_trim(0)`; `+MMmcs 0`; `MALLOC_ARENA_MAX=2`.

## Conflicts this ADR creates, to resolve in wave 0

1. **Cluster affinity against free gateway choice.** #4669 made an agent's home cluster sticky (`agent_routes.home_cluster_id`), so another cluster cannot claim and answer for it. D9 and D11 move agents between gateways freely, possibly across clusters.
   - Proposed resolution: once D5 holds, the server admits an agent through any gateway on the strength of the agent's own proof, and affinity becomes a placement preference instead of an admission rule.
   - Until D5 holds, affinity stays an admission rule.
2. **D5's scope.** Per-session signature or full message integrity (see D5).
3. **#5649.** D12 point 2 chooses stickiness on the gateway side (one owning server per agent). The reconcile must still be shown correct when that owner changes.
4. **ADR-0073's budget text.** It cites the 8 KiB goal, and must cite D14 instead before it goes to PR.

## Delivery plan

Each wave ends with the owner's guidance before the next starts. Pull requests target `dev` and merge by the repository's usual rules.

| Wave | Content | Done when |
|---|---|---|
| 0 | This ADR and ADR-2002 section 7h ratified; the four conflicts above decided; ADR-0073 to PR. A survey of what comparable products and projects do (SPIRE, Teleport, Tailscale, nginx/HAProxy with OpenSSL, 1E Tachyon, Tanium, ConfigMgr, Intune), recorded with the ADR. The memory-measures PR (split from the kTLS branch). | Owner sign-off. |
| 1 | The CA: SPIFFE-form identities; 24-hour agent and 7-day gateway and server certificates with renewal; importing a customer intermediate; the CRL served to gateways. Gateway and server move from pins to CA trust plus identity plus revocation, in both directions. | Both directions refuse a revoked, expired, wrong-role or wrong-CA peer, proven by test. |
| 2 | The agent edge: the enrollment port (token, or a machine certificate through CNG, Keychain or file); the strict main port; certificate and CRL checks in kTLS; the per-session agent signature checked by the server, plus whatever D5 settles. CI fuzzing, ASan, and the shared accept/refuse suite. | The shared suite passes on both TLS paths; 100 real Windows agents (rig100) enroll and connect with mutual TLS. |
| 3 | Topology: DNS discovery; the server-pushed gateway list; latency weighting; gateway drain (GOAWAY batches, enrollment port closed at the start); Erlang clustering on or off by deployment. | A drain moves every agent to other gateways within the window, with no lost command result. |
| 4 | Several servers: consistent hashing of agents to servers; the agent-to-gateway table; results through a different gateway; server drain; the ADR-2002 leader election wired in. | Two or more servers serve one fleet; one is killed and one is drained without losing an acknowledged result. |
| 5 | Postgres: a streaming-replication test rig with Patroni; failover tests. | Failover meets RPO zero and under 60 seconds of write downtime, under load. |
| 6 | The 100,000-agent run: the gateway on an 8-core, 16 GB allocation, load from Ngai-Syoon and the other test machines. | The D14 budget is met, or the gap is measured and explained. |

## Alternatives considered

- **One port that asks for a certificate but does not require one, at the agent edge.** This is what direct agent-to-server connections use. Rejected: every request needs a "did this connection present a certificate?" check, and one missed check is a hole. A separate port gives a guarantee the TLS layer enforces.
- **The customer's machine certificate on the main port.** Rejected for now. It ties certificate lifetimes, naming and revocation to the customer's PKI, needs a second path for customers without one, and runs into gRPC's PEM-only client key.
- **The gateway vouches for the agent, and the server trusts it.** Rejected: an internet-facing gateway that is compromised could impersonate every agent behind it.
- **Gateway-held fleet state, or a gateway mesh across the internet.** Rejected: membership in an Erlang cluster is full control of every member. This also respects the earlier ruling against new gateway state.
- **OTP `ssl` as the default.** Rejected by the owner, on the measured memory and handshake rate. It is kept as the fallback and as the reference the shared test suite compares against.

## Consequences

- The release that ships wave 2 breaks every existing agent-to-gateway deployment: new port, new certificates, agents re-enroll. This is acceptable only because there are no customers yet.
- The CA issues about 365 times as many agent certificates as today: a daily certificate instead of a yearly one. At 1.2 million agents that is about 14 signatures per second, around the clock. Its signing path, its `ca_issued` table and its CRL size must be measured before wave 2, not after.
- The gateway gains C code that faces the internet. The fuzzing, ASan and advisory-tracking requirements in D8 are permanent.
- `docs/pki-architecture.md`, `docs/user-manual/gateway.md`, the reference composes, the compose wizard and the agent installer all change with waves 1 to 3.

## Open questions

- The SPIFFE trust domain: derived from the CA fingerprint, or set by the operator.
- D5's final scope (see Conflicts).
- Whether to move kTLS handshakes out of the Erlang VM, into a separate OS process, so a memory-safety bug costs one handshake process rather than the gateway.
- Whether the CRL must become a delta or a bloom-filtered form at 1.2 million agents with 24-hour certificates.
- The ephemeral-port limit on load generators for wave 6: one source address to one gateway port gives about 16,000 connections on macOS defaults.
