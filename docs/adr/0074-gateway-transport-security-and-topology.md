# ADR-0074: Gateway transport security and topology: mutual TLS on every hop, SPIFFE identities, many gateways, many servers

- **Status:** Proposed. The owner's decisions below were taken on 2026-10-28 and 2026-10-29; the whole ADR needs the owner's sign-off at the end of wave 0.
- **Shipped:** nothing in D1 to D14. Today the agent-to-gateway hop is one-way TLS (see Context). Do not cite this ADR as a current capability.
- **Date:** 2026-10-28 (wave 0 decisions folded in 2026-10-29)
- **Authors:** Nathan Dornbrook
- **Supersedes:** nothing. Amends ADR-2002 (see its section 7h, added with this ADR). Amends ADR-2004 (the server identity form and the `mgmt_peer_auth_mode` default; see "Rules this design re-opens").
- **Related:**
  - ADR-0069 (the owned gRPC layer over Cowboy and gun, and the overload model), ADR-0066 (gRPC is the permanent transport).
  - ADR-2002 (high availability), ADR-0053 (the CA store on Postgres), ADR-0010 (secrets; the CA key stays behind `KeyProvider`).
  - ADR-0073 (draft: liveness-only heartbeat over a stateless gateway relay). It goes to PR after this ADR is ratified.
  - `docs/pki-architecture.md` (the current trust model and the per-hop TLS table).
  - Issues: #1292 and #5578 (cryptographic agent identity through the gateway; `docs/user-manual/gateway.md` tracks the agent-edge mutual TLS design there; D5 answers #5578's R-5, binding the identity to `agent_id`, and R-6, per-gateway `agent_id` scoping, is still open), #6016 (server identity by URI SAN, open), #5647 to #5651 (several upstream servers, open), #5649 (the reconcile decision, open), #4669 (agent-to-cluster affinity, closed).

## Context

### What runs today

| Hop | Today | Gap |
|---|---|---|
| Agent to server, direct | Mutual TLS. The agent presents its CA-issued leaf (`yuzu://<ca-fingerprint>/agent/<id>`, about a year, renewed at two thirds). Under the generated default certificates the port asks for a certificate but does not require one, so an unenrolled agent can bootstrap; the application enforces the rest. With operator-supplied certificates the port requires one (`server/core/src/grpc_tls_credentials.cpp`, `server.cpp`). | Only single-server installs use it. ADR-2002 section 2 makes the gateway mandatory in HA. |
| Agent to gateway (`:50051`) | One-way TLS (PKI PR5c). The gateway proves itself; it does not check the agent's certificate. The agent proves itself with its enrollment token, and heartbeats are bound to its Subscribe connection. | No transport identity for the agent at the edge that will face the internet. The enrollment token is presented only at first enrollment: the agent removes its token file once a registration is accepted (`agents/core/src/agent.cpp`), so after that an approved agent's `ProxyRegister` carries no per-agent secret. Revoking a gateway-proxied agent does not cut it off (`docs/auth-architecture.md`, "Gateway-proxied agents: revocation scope"). |
| Gateway to server (`:50055`) | Mutual TLS. The server admits the gateway by an SPKI pin fixed at boot. | Pins are per pair and do not scale to many gateways and many servers. No revocation. |
| Server to gateway management (`:50063`) | Strict mutual TLS. SPKI pin, or (opt-in, #6016) the server's URI SAN `yuzu://<install>/server` (the install id is derived from the CA fingerprint). | No CRL; a manual serial deny-list (`mgmt_peer_denied`) read at boot. Pins again. |

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
- **Enrollment port.** It accepts connections without a certificate, and the only thing it serves is enrollment. It has its own rate limit and connection cap at all times. The port is certless and faces the internet, so its cap must not be holdable by clients that never enroll: wave 2 must show that per-source limits (or an equivalent) keep it usable, and set a recovery target for a mass re-enrollment after an outage longer than a day.
- **Clean break.** This ships as a breaking change in the next release, with no fallback to the single-port behaviour. There are no production customers at the time of writing (2026-10-30); wave 2 re-checks this before it merges, and if a pilot runs agents through a gateway the upgrade note becomes a merge gate.
- **A routed-concern rule changes with it.** `.claude/routed-concerns-access-control.md` (the PKI row) forbids an `auth_fun` on the `:50051` agent listener, because it would reject every certless peer and stop agent bootstrap fleet-wide. That rule exists because today one port does both jobs. The change that splits the ports must amend the row in the same PR, with `security-guardian`: certless bootstrap moves to the enrollment port, which must never require a certificate.
- **Open: the direct port.** Whether the direct agent-to-server port of single-server installs gets the same split into an enrollment port and a strict main port. Wave 2 decides.

### D3. Identities are SPIFFE IDs

The URI SAN takes the SPIFFE form, `spiffe://<trust-domain>/<role>/<name>`. Examples: `spiffe://<trust-domain>/agent/<agent_id>`, `.../gateway/<name>`, `.../server/<name>`.

- **The trust domain (decided 2026-10-29)** is a random UUID generated once at install. The operator may set their own name at install time only; it never changes afterwards. It is not derived from the CA fingerprint: rotating the CA, or importing a customer intermediate (D4), would then rename every identity in the fleet. The SPIFFE standard itself advises a random name such as a UUID when no operator chooses one.
- **One URI SAN per certificate.** The SPIFFE X.509 standard says a verifier must reject a certificate with more than one. So the existing `yuzu://<ca-fingerprint>/agent/<id>` and `yuzu://<ca-fingerprint>/server` URIs cannot sit beside the new ones in one certificate. The migration is: verifiers accept either form for a window, then issuance flips to `spiffe://`. The CA alone chooses the SAN; a requester never does (`sign_agent_csr` already ignores the CSR's subject and SAN).
- **The role comes from the SPIFFE path, never from the EKU.** The same standard says that when a leaf carries an EKU it must list both `serverAuth` and `clientAuth`. So every leaf carries both, and the EKU no longer tells a gateway from a server or an agent. The management port's existing `serverAuth` check still passes; it simply stops being a role check.
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

The gateway checks the agent's certificate, but the server does not trust the gateway's word alone. The owner chose this so that a compromised internet-facing gateway can drop or delay traffic but cannot impersonate an agent, or forge or alter what passes between agent and server.

**Decided on 2026-10-29.** Three kinds of signature, together:

1. **Per session.** The agent signs a server-issued challenge at the start of every session with its own key. The server verifies the signature against the certificate it issued, and refuses a revoked or mismatched agent.
2. **Every command** is signed by the server that issues it, with that server's own CA-issued key (its SPIFFE ID, `.../server/<name>`). The agent verifies it whichever server sent it and whichever gateway carried it.
3. **Every result** is signed by the agent. **The gateway list and drain suggestions** (D9, D11) are server-signed in the same way.

Each signature is over the whole message: for a command, the plugin, action and parameters; for a result, its status and payload; for the gateway list, the list itself. Each also binds the agent id, the command or execution id, the signer's identity and an expiry. The per-session signature covers the server's challenge. How an agent learns that a server's signing key is revoked is not yet designed; wave 2 decides.

A replayed command is a duplicate to ADR-2002 WS-0's durable command idempotency only while WS-0's terminal ring still holds it (a bounded ring, `kMaxDedupRows` in `command_dedup_store.hpp`), and only while the agent's dedup store is healthy: a degraded store fails open by design (`docs/command-dedup.md`). So a signature's expiry must stay inside the dedup window, and wave 2 must either refuse signed commands while dedup is degraded or record that residual. The expiry also bounds how long a gateway can hold a command back. Liveness heartbeats stay unsigned.

Why signed messages rather than a key agreed per session with a MAC on every message: any server may send a command straight to the gateway that holds the agent (D12), and a drained agent delivers its result through another gateway, in another session, possibly to another server (D11, D12). A signed message survives both unchanged; a per-session key would have to be shared between servers, which is a new secret store. A signed result kept in Postgres is also evidence anyone can check later from the agent's key, which a MAC is not. The survey below found the same rule elsewhere: a relay that must read, store and forward messages (TUF mirrors, Tailscale's Tailnet Lock key distribution) uses signed messages; a relay that moves opaque bytes (WireGuard through Tailscale's DERP relays, SSH through Teleport's proxy) uses a per-session key.

**What D5 deliberately does not give, stated plainly:**
- **Confidentiality from the gateway.** The gateway still reads commands and results in plaintext. Hiding them would need encryption to the agent's key, a separate decision for SaaS.
- **Honest heartbeats.** A compromised gateway can report a dead agent as alive. The lie lasts until the next signed result or the next session start.
- **Reading payloads.** D5 does not stop a gateway that holds the agent from reading command payloads (the first point above).

**To measure in wave 2:** the agent's cost of signing each result, and the server's verification rate, at the result rate of the 5,000-agent rig, alongside D14's handshake budget.

### D6. Certificate lifetimes and revocation

- **Agent certificates** last 24 hours and are renewed at half-life. At 100,000 agents per gateway, renewing every 12 hours, that is about 2.3 renewals per second per gateway.
- **Expired certificates.** An agent whose certificate expired (a server outage longer than a day, or a laptop off over a weekend) cannot use the main port and must go back through the enrollment port. Wave 1 must decide whether a recently expired certificate may renew there on its own key, and wave 2 must measure a mass re-enrolment after an outage. Prior art for renewing on its own key: Teleport's bound-keypair joining, where a bot whose certificates lapsed signs a server challenge with its bound private key, a generation counter refuses a cloned credential, and automatic recoveries are capped.
- **Gateway and server certificates** last 7 days, on the same revocation list.
- **Revocation scope, not yet settled.** With renewal at half-life an agent holds two valid leaves for about 12 hours, so revoking one serial leaves the other valid. Today's block on re-issuing to a revoked agent (`server.cpp`) lasts until the revoked certificate's notAfter, so with 24-hour certificates it lapses within a day instead of about a year. And with CRL pruning (D7) plus renewal on an expired certificate's own key, a revoked and expired agent is on neither list. Wave 1 must state the revocation scope (every live serial of an identity) and what blocks re-issuance (the append-only revoked set and the agent DENY, never the published CRL).
- These replace today's one-year agent leaf and the server and gateway leaves sized to the CA's life.

### D7. Revocation at a gateway that keeps no state of its own

- The gateway pulls the revocation list from the server every 60 seconds and refuses revoked agents at the handshake. That stops a revoked agent before it costs a session, memory and an upstream call.
- It keeps the last good list if a pull fails, and fails closed (refuses new agent handshakes) after 15 minutes without a good pull.
- **The gateway's own hop must survive a stale list.** D1.3's revocation check on the gateway-to-server hop, combined with a stale CRL, could lock a gateway out of the server it needs for a fresh list. Wave 1 must show that a gateway with a stale list can still fetch a fresh one; the 15-minute fail-closed refuses new agent handshakes only.
- **Under several servers (D12),** the server that owns an agent's stream must learn of a revocation made on another server. How is not yet designed; wave 5 decides.
- The server ends a revoked agent's live session immediately.
- **The window a revoked agent still has, stated plainly:** up to one poll (60 s) when everything is up; about two minutes across a Postgres failover (D13's 60 s plus a poll); up to 15 minutes when the gateway can reach no server, which is the fail-closed bound. The server's own check at session start (D5) closes it earlier whenever the server is reachable.
- **Two 15-minute clocks coincide:** the CRL's fail-closed bound and the gateway's CONNECTED resend, which slows after 15 minutes of refusals (`notify_unacked_slow_after_ms`). An outage of 20 to 30 minutes with revocation on must be tested.
- The list is the CRL `CaStore::publish_next_crl` already publishes (ADR-2002 section 8).
- **CRL signing becomes a 15-minute dependency.** A 15-minute nextUpdate (see the test below) means the server must re-sign the CRL at least every 15 minutes, so CRL freshness then depends on the CA key, a Postgres write and the leader. Today the CRL carries a 7-day nextUpdate and is re-published about every 6 days, from a leader-gated tick (`crl_publisher.cpp`, `server.cpp`). With D13's never-degrade rule, losing the synchronous standby for more than 15 minutes would make every gateway fail closed for new agents. Whether the owner accepts that coupling, or CRL signing is decoupled, is open.
- **Expired entries leave the CRL (decided 2026-10-29).** The published CRL drops a revoked certificate only after it has appeared on one scheduled CRL issued after its notAfter, as RFC 5280 allows. The revoked rows in `ca_issued` stay append-only, exactly as today: only the published list shrinks, never the table. With 24-hour agent certificates the list then only holds certificates revoked in about the last day. Even 1% of 1.2 million agents revoked in one day is about 12,000 entries, roughly 0.45 MB, so no delta or Bloom-filter form is needed. A mass revocation (every agent behind a compromised gateway, a fleet-wide re-key) is handled by rotating the issuing intermediate, not by growing the list. A default install has no issuing intermediate: it signs leaves from the Yuzu root, and Yuzu never signs CA intermediates itself (`docs/pki-architecture.md`). So in a default install a mass revocation is a root rotation, unless wave 1 adds an issuing intermediate under the root. Wave 1 decides.
- **A routed-concern rule changes with it, in wave 1, not now.** The PKI row in `.claude/routed-concerns-access-control.md` says each CRL is a superset of the last. Pruning by expiry breaks that wording, though not the append-only table under it. ADR-2002 section 8 says the same (each CRL is a superset of the one before it), and wave 1 amends that sentence too. Pruning also breaks the count-based CRL freshness self-heal: `has_unpublished_revocations` (`ca_store.cpp`) compares the latest CRL's revoked count with the revoked rows, so wave 1 must re-key it to the non-expired revoked set in the same change. The wave-1 change that prunes the CRL amends the row in the same PR, with `security-guardian`.
- **To test in wave 1:** if the CRL's nextUpdate is set 15 minutes ahead, OpenSSL itself refuses a stale list, so the 15-minute fail-closed bound becomes a property of the signed CRL, the same on both TLS paths.
- **Customer intermediates (D4):** checking every level of the chain needs a CRL from the customer's root for the intermediate, which Yuzu cannot produce. Either the leaf alone is checked, or the customer supplies their root's CRL; wave 1 decides.

### D8. kTLS is the default at the agent edge; OTP `ssl` is the fallback

The reasons are the measurements above, and that nginx and HAProxy run the same design: OpenSSL's TLS state machine and X.509 code in their own process, then (where enabled) kernel record encryption. **Neither makes kTLS a default (verified 2026-10-29).** nginx offers it as an opt-in since 1.21.4 (2021), through `ssl_conf_command Options KTLS`. HAProxy offers it as an experimental option since 3.3 (2025), through `ktls on`, refused unless the configuration also sets `expose-experimental-directives`. Our default is therefore a stronger position than either, but only if the requirements below are met; they are what make it acceptable. HAProxy, like the gateway, is one multi-threaded process, so a memory-safety bug there also costs every connection; nginx isolates it to one worker.

**TLS version.** TLS 1.2 sends the client certificate in the clear, so on an internet-facing gateway a passive observer reads every agent's SPIFFE ID. That argues for TLS 1.3 on the main port. A TLS 1.3 peer can send KeyUpdate to change keys mid-connection. Under kTLS the kernel must install the new receive key, and only newer kernels can (the rekey support is documented for Linux 6.14). Rocky 9's 5.14 cannot: there a KeyUpdate ends the connection (BigColin K2, 2026-10; no Yuzu agent stack was seen to send one). If wave 2 chooses TLS 1.3 it needs two things:
- **A KeyUpdate policy:** refuse it and close the connection, or require a kernel with rekey support on gateway hosts, or keep the receive side in user space.
- **A KeyUpdate rate limit** whatever the policy, because each KeyUpdate costs CPU. HAProxy added one (100 per second per connection by default) to stop a KeyUpdate flood; the lesson applies with or without kTLS.

Because memory safety is vital, these are requirements, not options:
- a pinned OpenSSL version, with its security advisories tracked and acted on;
- continuous fuzzing of our C code in CI, plus an ASan build exercised by the test suite. These apply to gateway C from the trim NIF onward, not from wave 2; no CI job covers gateway C today. Wave 0 adds a fuzz harness and an ASan run for the trim NIF, and wave 2 extends both to the kTLS NIF;
- one shared test suite proving the kTLS and OTP `ssl` paths accept and refuse exactly the same certificates (chain, SAN, EKU, expiry, revocation);
- security review of the C code before it ships enabled.

The difference from nginx is recorded: nginx runs handshakes in worker processes, so a crash costs one worker. Our handshake runs inside the Erlang VM, so a crash costs the gateway. Whether to move handshakes out of the VM later is an open item (see Open questions).

**Where the agent-certificate checks run (decided by Nathan on 2026-10-28):**
- **In C:** OpenSSL checks the chain and the revocation list during the handshake. The NIF sets `SSL_VERIFY_PEER` with fail-if-no-peer-certificate, the CA store (Yuzu root or customer intermediate) and the CRL. A bad chain or a revoked certificate is refused before the handshake completes. Our C stays small: configuring OpenSSL and handing the verified peer certificate to Erlang.
- **In Erlang:** the gateway checks the SPIFFE identity and the EKU of the verified certificate just after the handshake, before any gRPC request is served. Identity rules will change as SPIFFE and customer intermediates arrive, so they live where they are easy to change and test.
- **The same split on the fallback path:** OTP `ssl` checks chain and CRL, and the same Erlang identity check runs. The shared accept/refuse suite covers both.

The kTLS branch (`perf/gateway-idle-mem-ktls`, not on `dev`) currently refuses `ktls` together with `verify_peer`; that refusal goes away.

### D9. Discovery and choosing a gateway

- **"Use DNS" is a design principle.** An agent finds its first gateway by DNS.
- **After first contact,** the server gives the agent the current gateway list, with weights and draining state. The agent caches it on disk for the next start.
- **Choosing:** weighted random choice, with the weight from measured round-trip time, so the nearest gateway in time weighs most and agents do not all pile onto one. Jittered back-off between attempts. Failover down the list.
- **Draining gateways** have weight zero.
- No region or site field in the first version: latency weighting covers it. The weight function stays pluggable, because round-trip time does not see a LAN boundary (a per-campus site gateway, for example).
- **When every cached entry fails** (all drained or dead), the agent goes back to DNS. The cached list carries an expiry; to be set in wave 4, preferably per entry by the server, as Teleport's proxies do.
- **Any gateway list that reaches the agent through a gateway is signed by the server** (D5), and the agent refuses one that is not. Otherwise a compromised gateway could steer agents to endpoints of its choosing. Those could not impersonate the server, but they could hold agents captive.

### D10. How gateways know about one another

- **Inside a corporate network:** gateways may form an Erlang cluster (the existing `yuzu_gw_cluster_discovery` and hash ring). The cluster's own connections run over TLS (`inet_tls_dist`) with CA-issued certificates. Membership in an Erlang cluster is full control of every member. D1.2's role check applies: distribution admits only gateway identities carrying the cluster's id, with chain and CRL checked. Under D3 agent leaves carry both `serverAuth` and `clientAuth` and chain to the same CA, so a chain-only check would admit an agent leaf to the cluster.
- **Outside, including every internet-facing gateway:** gateways never talk to each other. They coordinate only through the server. Erlang clustering is off by default for an internet-facing gateway.
- **Either way,** every gateway reports health, load and draining state to the server, because the server owns the gateway list agents receive (D9).

### D11. Draining a gateway

1. **The order:** an operator issues it through the dashboard, REST API or MCP, RBAC-gated and audited, reaching the gateway through the server (or through the cluster). Automation uses the same API.
2. **What agents receive (decided 2026-10-29):** the gateway sets its weight to zero. Each agent first receives, on its own stream, a short suggested list of other gateways signed by the server (D5). Then the gateway sends an HTTP/2 GOAWAY in two phases: a first one that stops new streams, and a final one after a jittered delay. The GOAWAY carries nothing in its debug data: RFC 9113 says that data is for diagnostics only, and the agent's gRPC stack does not hand it to the application. The agent reconnects by its normal weighted choice.
3. **Pace:** the two-phase GOAWAY goes out in staggered, jittered batches over an operator-set window, 10 minutes by default, so no other gateway takes a storm. The gateway exits when empty or at a hard deadline.
4. **Commands in flight:** the agent reconnects elsewhere and delivers the result there. The server must accept a result for a command it sent through a different gateway. The durable command idempotency of ADR-2002 WS-0 and the execution ids carry it.
5. **The enrollment port** stops accepting new connections at the start of the drain window.

### D12. Several servers

1. **All servers active.** Singleton jobs run on the elected leader of ADR-2002 sections 3 and 6.
2. **Each gateway connects to every server** (ADR-2002 section 7g). Each agent's stream goes to one server, chosen by consistent hashing on `agent_id`. When a server is lost or drained, only its agents move.
3. **Reaching an agent:** Postgres records which gateway holds which agent (`agent_routes`). Any server sends a command straight to that gateway's management port. **This is new server code.** As of `origin/dev@fbd8b5409`, `AgentRegistry::send_to` (`server/core/src/agent_registry.cpp`) returns false for an agent not in that server's own memory, so a dispatch handled by a server that does not own the agent reaches nobody. With N gateways each connected to M servers, the upstream permit model (#6057) must also be re-derived. The result returns through the server that owns the agent's stream and lands in Postgres.
4. **Gateways find servers by DNS.**
5. **Draining a server:** it stops taking new agent streams, and its agents are rehashed onto the others in staggered batches.

### D13. Postgres

- **Replication:** one synchronous standby plus any number of asynchronous ones. Writes never fall back to the primary alone (ADR-2002 sections 11 and 13: no acknowledged-write loss while the synchronous quorum holds). This conflicts with the shipped default (conflict 8): until wave 6 reconciles the two, the shipped default is unchanged.
- **Failover:** Yuzu depends on no particular HA tool. It reaches Postgres by one DNS name, or a multi-host DSN, with `target_session_attrs=read-write`. Patroni is the documented on-premises reference; a managed service is the SaaS choice. RPO zero needs failover to promote only a synchronous standby, so whatever HA tool is used must enforce that.
- **Targets:** RPO zero for acknowledged writes; write downtime under 60 seconds per failover. These are targets, unmeasured until wave 6. While Postgres is unreachable, servers fail closed for writes. **That is not true of every store today:** `ResponseStore` logs a failed store under pool pressure and drops the response (BigColin RR7, 2026-10-28: one of seven runs lost 1,989 of 4,941 responses with the default pool of 16). A synchronous standby lengthens every commit and makes that likelier. This decision therefore includes a concrete change: bounded retry, or an explicit error, for response storage, and a pool size measured against a synchronous standby.
- **Reads:** no reads from standbys in the first version.
- **Leadership** is re-elected after every failover, and every singleton job must tolerate that.
- **Several servers need more than this ADR.** Multi-server operation (D12, wave 5) also requires ADR-2002's safe-to-scale gate (`docs/ha-delivery-matrix.md`, including #6528 and #6535). Wave 5's rig does not lift it.

### D14. The gateway budget

This replaces the 8 KiB-per-connection goal set on 2026-10-26.

These are targets, not yet evidence. On merged `dev` the gateway holds about 320 to 470 KB per agent at 5,000 agents (Nathan's 5,000-agent suite; BigColin RR7, RSS). The 48.1 KB above is the kTLS branch at 100 agents with one-way TLS. Wave 0 measures a common baseline at 5,000 and 10,000 agents, with one method (OS anonymous memory plus kernel, after settling, TLS on), on merged `dev` and on the kTLS branch, before the CI check becomes a gate.

- **Goal, per box:** one gateway on 8 cores and 16 GB holds 100,000 idle agents with mutual TLS. It must stay inside:
  - memory under 8 GB;
  - idle CPU under 2 cores;
  - a full reconnect of all 100,000 agents within 60 seconds (about 1,700 handshakes per second, plus the D5 signature checks). RR7 registered about 290 agents per second against the about 1,700 needed; the likely bottleneck is the server's Register path (and the D5 verification, whose CPU cost is not yet budgeted), not the handshake;
  - memory back within 5% of its pre-storm level within 2 minutes.
- **CI regression check, per agent:** 64 KiB per idle agent, all-in including the kernel's per-connection memory. The check is measured with the ADR-0073 heartbeat (liveness only, no fleet snapshot), so until ADR-0073 lands it does not measure the heartbeat that ships.

The memory measures in this ADR's companion change (on `dev` since commit 857ac374e) are: a garbage collection of the large processes after an agent-count drop, plus a second pass 30 seconds later; and a periodic `malloc_trim(0)` through a small NIF. The trim acts on glibc only, and does nothing on the default musl image. `+MMmcs 0` and `MALLOC_ARENA_MAX=2` are not in it: they are deferred to the hibernation work, because they gave no measurable memory gain and had a measured idle-CPU cost.

`malloc_trim` is a glibc feature. It acts on the chiselled Ubuntu image (`Dockerfile.gateway.chisel`), where it was measured. The default image (`Dockerfile.gateway`) is Alpine with musl, and musl has no `malloc_trim`. musl's allocator returns freed memory differently, and that is not yet measured. The glibc builders (the chisel builder, CI, and the Meson-driven gateway build on Linux) already compile the trim NIF (`gateway/apps/yuzu_gw/rebar.config`, `c_src/build_mem_trim_nif.sh`). Only the Alpine builder in `Dockerfile.gateway` has no C toolchain; the kTLS NIF must add one there (`build-base`, `openssl-dev`, `linux-headers`). Both NIFs are Linux-only: Windows and macOS gateway builds skip them. kTLS itself does not need glibc. Checked on 2026-10-28: the NIF builds without warnings against musl in `erlang:28-alpine` (with `openssl-dev` and `linux-headers`) and loads in the BEAM there. What kTLS needs is the host kernel's `tls` module, because a container shares the host's kernel and cannot load modules itself.

### Rules this design re-opens

Several standing rules, and one earlier ADR, say the opposite of a decision above. Until the named wave amends each one, with `security-guardian`, the current rule stands and code must follow it.

- **No `auth_fun` on the `:50051` agent listener** (the PKI row of `.claude/routed-concerns-access-control.md`; D2). It is also enforced in code: the gateway refuses to boot with `auth_fun_on_agent_listener` (`yuzu_grpc_listener.erl`), and the manual's stage 3 in `docs/user-manual/gateway.md` ("Moving the agent edge to mutual TLS") says the same. The enrollment port also needs a per-listener method allow-list, which the layer does not have: new code. **Wave 2.**
- **Each CRL is a superset of the last** (the PKI row; D7). **Wave 1.**
- **The gateway-upstream peer row,** clause (2) (CA membership never substitutes for the pin) and clause (3) (pins fixed at boot, no revocation read, and re-opening them means re-opening `docs/security-reviews/gateway-peer-authz-minimal-2026-10-07.md`). D1 re-opens both. **Wave 1.**
- **The mgmt-plane peer row and ADR-2004:** clause (2), one byte-exact identity `yuzu://<install>/server`, against D3's window that accepts both forms and its per-instance `.../server/<name>`; clause (3), an unset `mgmt_peer_auth_mode` is always `pin`, against D1's optional pins; clause (4), `identity_over_ca_bundle` refuses a CA file that is not exactly one certificate, which a customer intermediate plus its root (D4) is; and the identity derived from the CA fingerprint, against D3's UUID trust domain. **Wave 1.**
- **Alternatives ADR-2004 rejected and this ADR takes up:** short-lived server certificates (rejected there because the server never renews its leaf and client credentials have no hot reload), and CRL checks at the handshake only on the long-lived management connection. So wave 1 must add credential hot reload on server and gateway, and the teardown of a live connection whose peer certificate is revoked.

## Conflicts this ADR creates, to resolve in wave 0

1. **Cluster affinity against free gateway choice. Decided on 2026-10-29: affinity is dropped.** #4669 made an agent's home cluster sticky (`agent_routes.home_cluster_id`), so another cluster cannot claim and answer for it. D9 and D11 move agents between gateways freely, possibly across clusters. From wave 4 the choice of gateway is free, and affinity is no longer an admission rule, nor kept as a preference.
   - **The risk this carries, stated plainly:** until D5 lands in wave 2, a compromised gateway that holds a valid gateway certificate can claim any agent's route. D5's per-session signature and signed commands and results close it only if the route write (`agent_routes`, written today on the gateway's CONNECTED notification and asserted by the gateway) changes only after the server has verified that session's agent signature. Wave 2 makes it so. D5 does not stop a gateway that holds the agent from reading command payloads (a D5 non-goal).
   - **Which wave removes the #4669 admission check is not yet named.** The drop is decided, gateway choice is free from wave 4, and the route-claim risk runs until D5 lands in wave 2.
2. **D5's scope. Decided on 2026-10-29:** signed commands, signed results and a signed gateway list, on top of the per-session signature (see D5).
3. **#5649. Still open: a proof obligation for wave 5.** D12 point 2 chooses stickiness on the gateway side (one owning server per agent). Wave 5 must show the reconcile correct when that owner changes (server loss or drain).
4. **ADR-0073's budget text.** It cites the 8 KiB goal, and must cite D14 instead before it goes to PR. Its gateway citations also predate the merge of PR #5695 and must be re-cited.
5. **"The gateway adds no state." Decided on 2026-10-29:** both this ADR and ADR-0073 say instead that the gateway keeps **no per-agent state beyond the connection**. Fleet-level state that any gateway could rebuild is allowed: the cached CRL, the drain flag, the cached gateway list, and cluster membership. ADR-0073 is reworded to match before it goes to PR.
6. **Erlang clusters and the server's `cluster_id`. Decided on 2026-10-29: one Erlang cluster is one `cluster_id`.** The server already routes by a `cluster_id` per gateway session (ADR-2002 WS-4 4.3). Every member of a cluster (D10) is configured with the same id, and a node configured with a different id refuses to join.
7. **The design target.** ADR-0069 records 100,000 agents per gateway. Dave has been steering to a solid 5,000 per gateway now, nothing that blocks 50,000 and beyond, and 500,000 as the long-term horizon. **Decided by Nathan on 2026-10-28** (Dave to see): waves 1 to 5 must pass at 5,000 agents on both rigs, with nothing that blocks 50,000; wave 6 tests failover under a 5,000-agent load; wave 7 is the 100,000-agent per-box budget (D14); 500,000 stays the long-term horizon, outside this programme.
8. **D13 against ADR-2002 section 11. Still open: for wave 6.** Section 11's default is one primary plus two synchronous standbys (`ANY 1`), with an async profile as a documented opt-out (section 13 keeps it). WS-7 measured that strict no-degrade mode blocks writes for minutes after a single failover, against D13's 60-second target, so the shipped default is async with degrade on total standby loss (`YUZU_PG_SYNC_STRICT` defaults to false in `deploy/docker/ha-postgres/patroni-entrypoint.sh`). D13 supersedes section 11's default and its async opt-out only once wave 6 reconciles the two, or revises one of them. Until then the shipped default is unchanged. Wave 6 works on the existing Patroni rig (`deploy/docker/docker-compose.ha-postgres.yml`), not a new one.

## Audit and evidence

The waves add audit records or metrics for: certificate issuance, renewal and revocation; CRL publication and gateway pulls; handshake refusals by reason; entry into and exit from fail-closed; enrollment by machine certificate; D5 signature refusals; and the drain lifecycle (order, abort, completion). Each wave names its own audit verbs and metrics. Mutations fail closed on audit failure (ADR-1005).

## Accepted risks

Each is re-accepted at the owner's sign-off at the end of wave 0.

| Risk | Accepted by, date | Scope | Ends when |
|---|---|---|---|
| A compromised gateway with a valid gateway certificate claims any agent's route (conflict 1). | Nathan Dornbrook, 2026-10-29 | Every gateway-proxied agent, until D5. | Wave 2, once the route write depends on the server's verification of the session's agent signature. |
| The gateway reads commands and results in plaintext, and can report a dead agent as alive (D5's non-goals). | Nathan Dornbrook, 2026-10-29 | Every gateway-proxied agent. | Not ended in this programme: confidentiality from the gateway is a separate SaaS decision; a false heartbeat lasts until the next signed result or session start. |
| A revoked agent keeps working for up to 60 s, about 2 minutes across a Postgres failover, or up to 15 minutes when the gateway reaches no server (D7). | Nathan Dornbrook, 2026-10-28 | New and live sessions behind a gateway. | Not ended: these are the design's bounds. Wave 1's Done-when proves them by test. |

## Review of 2026-10-28 (BigColin session, for Dave Rae)

A review of the decisions record and ADR-0073 against BigColin's measurements (`yuzu-test-results/REVIEW-NATHAN-MTLS-TOPOLOGY-ADR-0073-2026-10-28.md`, private share; RR7 at merged `dev@73369c123`, 5,000 agents) was folded in above: the auth_fun row (D2), renewal rates and expired certificates (D6), the revocation window and the two 15-minute clocks (D7), the nginx and HAProxy correction and the TLS version (D8), the DNS fallback and pluggable weight (D9), the new server code in D12, response storage in D13, the baseline before the budget gates (D14), and conflicts 5 to 7.

Three proposals change the plan. All three were accepted by Nathan on 2026-10-28; Dave has still to see them:
1. **Accepted by Nathan on 2026-10-28; now wave 3 of the plan.** A server wave before topology work, fixing what makes moves between gateways and servers lossy today. With an agent on two gateways at once, about 50 agents' routes were lost in 8 of 8 RR7 runs. Response storage drops under pool pressure. The in-memory registry lags Postgres for up to two seconds after a restart.
2. **Accepted by Nathan on 2026-10-28; now in waves 1 and 2.** Measure the Register rate and certificate issuance against the real server in waves 1 and 2, plain and with mutual TLS, with the pool at 16 and 64. RR7 registered 5,000 agents in 17.0 s (about 290 per second); D14 needs about 1,700 per second.
3. **Accepted by Nathan on 2026-10-28; now in wave 0.** The common memory baseline first (D14): OS anonymous memory plus kernel per-connection memory, after settling, TLS on, realistic heartbeats, at 5,000 and 10,000 agents, on merged `dev` and the kTLS branch, run on both BigColin's rig and ours.

## Delivery plan

Each wave ends with the owner's guidance before the next starts. Waves 1 to 6 are gated at 5,000 agents on both rigs (conflict 7); wave 7 at 100,000. Pull requests target `dev` and merge by the repository's usual rules.

| Wave | Content | Done when |
|---|---|---|
| 0 | This ADR and ADR-2002 section 7h ratified; the conflicts above decided; ADR-0073 to PR. A survey of what comparable open-source projects and commercial endpoint platforms do (done 2026-10-29; the open-source half is recorded below). The memory-measures PR (split from the kTLS branch). A fuzz harness and an ASan run for the trim NIF (D8). The common memory baseline (D14), on both rigs. | Owner sign-off. |
| 1 | The CA: SPIFFE-form identities; 24-hour agent and 7-day gateway and server certificates with renewal; importing a customer intermediate; the CRL served to gateways. Gateway and server move from pins to CA trust plus identity plus revocation, in both directions. Measured: the CA's signing rate, and the Register rate against the real server with one-way TLS, Postgres pool 16 and 64. | Both directions refuse a revoked, expired, wrong-role or wrong-CA peer, proven by test. The measured rates are recorded; if they fall well short of about 1,700 per second, D14's 60-second target is revised or the bottleneck found before wave 2. |
| 2 | The agent edge: the enrollment port (token, or a machine certificate through CNG, Keychain or file); the strict main port; certificate and CRL checks in kTLS; D5's per-session agent signature checked by the server, server-signed commands and agent-signed results. CI fuzzing, ASan, and the shared accept/refuse suite. Measured: the Register rate with mutual TLS and the per-session signature, and a mass re-enrolment after a simulated outage. | The shared suite passes on both TLS paths; 100 real Windows agents (rig100) enroll and connect with mutual TLS. |
| 3 | The server, before agents move: an agent seen on two gateways at once must not lose its route (RR7: about 50 of 5,000 lost in 8 of 8 forced-move runs); response storage must not drop under pool pressure; the in-memory registry must not lag the Postgres routes after a restart. Accepted by Nathan on 2026-10-28 from the BigColin review. | The RR7 forced-move, pool-pressure and post-restart cells pass with no loss, on BigColin's rig and ours. |
| 4 | Topology: DNS discovery; the server-pushed gateway list, server-signed, and the server-signed drain suggestion (D5); latency weighting; gateway drain (GOAWAY batches, enrollment port closed at the start); Erlang clustering on or off by deployment. | A drain moves every agent to other gateways within the window, with no lost command result. |
| 5 | Several servers: consistent hashing of agents to servers; the agent-to-gateway table; results through a different gateway; server drain; the ADR-2002 leader election wired in. | Two or more servers serve one fleet; one is killed and one is drained without losing an acknowledged result. |
| 6 | Postgres: on the existing Patroni rig (`deploy/docker/docker-compose.ha-postgres.yml`), reconcile D13 with ADR-2002 section 11 (conflict 8); failover tests. | Failover meets RPO zero and under 60 seconds of write downtime, under load. |
| 7 | The 100,000-agent run: the gateway on an 8-core, 16 GB allocation, load from Ngai-Syoon and the other test machines. | The D14 budget is met, or the gap is measured and explained. |

## Survey of comparable projects (2026-10-29)

Wave 0 compared this design with open-source systems that answer the same questions. Only public, open-source sources are cited here; findings about commercial endpoint platforms were gathered too, and inform the decisions, but are not named. Versions as seen on 2026-10-29.

| Question | What the projects do | What it means here |
|---|---|---|
| Identity format and trust domain (D3) | [SPIFFE](https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE-ID.md): the operator chooses the trust domain; an automatically generated one should be random, such as a UUID. [X.509 SVIDs](https://github.com/spiffe/spiffe/blob/main/standards/X509-SVID.md) carry exactly one URI SAN, and a leaf's EKU, when present, lists both `serverAuth` and `clientAuth`. [Envoy's SPIFFE validator](https://github.com/envoyproxy/envoy/blob/main/api/envoy/extensions/transport_sockets/tls/v3/tls_spiffe_validator_config.proto) picks the trust bundle by the presented trust domain. | A random install UUID; one SAN, so the `yuzu://` migration accepts both forms for a window; role from the path, not the EKU. |
| Bootstrap with an existing machine certificate (D2, D4) | [SPIRE](https://github.com/spiffe/spire/blob/main/doc/plugin_server_nodeattestor_x509pop.md)'s `x509pop` node attestor checks that a pre-provisioned certificate chains to a trusted CA and issues a signature challenge for proof of possession; `tpm_devid` does the same for a TPM. None of the projects found puts certificate-less bootstrap on its own port; nginx's equivalent of today's single port is `ssl_verify_client optional`. | D4 has direct prior art. D2's separate port is stricter than the norm, not behind it. |
| Lifetimes and renewal (D6) | SPIRE: 1-hour SVIDs, renewed at half-life. [Linkerd](https://github.com/linkerd/linkerd2/blob/main/charts/linkerd-control-plane/values.yaml): 24 hours, refreshed at 70% of the remaining life. [Teleport](https://goteleport.com/docs/reference/machine-workload-identity/configuration/) Machine ID: 1 hour by default, capped at 24; its [bound-keypair joining](https://goteleport.com/docs/reference/machine-workload-identity/bound-keypair/concepts/) lets a lapsed bot recover with its bound key, a generation counter and a recovery limit. | 24 hours at half-life is mainstream. Bound keypair is the model for a recently expired renewal. |
| Revocation (D7) | SPIRE, Linkerd and Teleport use no per-certificate CRL for short-lived leaves: SPIRE bans or evicts a node so it cannot renew, and rotates an authority for mass revocation; Teleport uses [locks](https://goteleport.com/docs/identity-governance/locking/), fail-open by default with a `strict` mode. nginx (`ssl_crl`) and HAProxy (`crl-file`, replaceable at run time) check CRLs through OpenSSL. [RFC 5280](https://www.rfc-editor.org/rfc/rfc5280) allows an entry to leave the CRL one scheduled CRL after the certificate expires. | Prune expired entries; no delta or Bloom form needed; rotate the intermediate for a mass revocation. D7's fail-closed bound is stricter than the norm. |
| kTLS and memory safety (D8) | [nginx](https://nginx.org/en/CHANGES): kTLS opt-in since 1.21.4 (`ssl_conf_command Options KTLS`); work isolated per worker process. [HAProxy](https://github.com/haproxy/haproxy/blob/master/doc/configuration.txt): `ktls on`, experimental since 3.3; one multi-threaded process; a KeyUpdate rate limit (`tune.ssl.keyupdate-rate-limit`). Both are fuzzed in OSS-Fuzz, but the public harnesses target HTTP parsing, not TLS glue. [Linux kTLS](https://docs.kernel.org/networking/tls.html) pauses decryption on a KeyUpdate until user space installs the new key. | Our kTLS default is stronger than both; a KeyUpdate policy and rate limit are needed; our fuzzing of the NIF goes beyond what either publishes. |
| Handshakes out of process (open question) | OpenBSD [relayd](https://github.com/openbsd/src/blob/master/usr.sbin/relayd/ca.c) and Envoy's private-key providers isolate the private key, not the handshake parser. nginx isolates by worker process. Linkerd avoids OpenSSL with a memory-safe stack. None runs a disposable process per handshake. | If done, the nginx-shaped form: a small pool of handshake processes handing the established socket back. |
| Integrity through a relay (D5) | [WireGuard](https://www.wireguard.com/protocol/) through [Tailscale DERP](https://tailscale.com/kb/1232/derp-servers), and SSH through Teleport's proxy in [node recording mode](https://goteleport.com/docs/reference/architecture/session-recording/), encrypt and authenticate every packet under a session key: the relay moves opaque bytes. [TUF](https://theupdateframework.github.io/specification/latest/) and Tailscale's [Tailnet Lock](https://tailscale.com/kb/1226/tailnet-lock) sign objects with freshness, because the intermediary stores and forwards. | The gateway parses, routes and redelivers, so it is the second kind: signed commands, results and lists. |
| Discovery, drain and routing (D9, D11, D12) | Teleport's [reverse-tunnel discovery](https://github.com/gravitational/teleport/blob/master/lib/reversetunnel/discovery.go) gossips the proxy list with a server-set expiry; its [proxy peering](https://goteleport.com/docs/zero-trust-access/management/proxy-peering/) keeps agent-to-proxy routes in the backend. Tailscale picks a relay by latency, next-closest on failure. [gRPC A9](https://github.com/grpc/proposal/blob/master/A9-server-side-conn-mgt.md) jitters connection age by ±10%. [Envoy](https://github.com/envoyproxy/envoy/blob/main/api/envoy/extensions/filters/network/http_connection_manager/v3/http_connection_manager.proto) drains with a two-phase GOAWAY and optional jitter. [RFC 9113](https://www.rfc-editor.org/rfc/rfc9113) gives GOAWAY debug data no meaning. | Matches D9 and D12. D11's list moves out of GOAWAY into a signed message on the stream. |

## Alternatives considered

- **One port that asks for a certificate but does not require one, at the agent edge.** This is what direct agent-to-server connections use. Rejected: every request needs a "did this connection present a certificate?" check, and one missed check is a hole. A separate port gives a guarantee the TLS layer enforces.
- **The customer's machine certificate on the main port.** Rejected for now. It ties certificate lifetimes, naming and revocation to the customer's PKI, needs a second path for customers without one, and runs into gRPC's PEM-only client key.
- **The gateway vouches for the agent, and the server trusts it.** Rejected: an internet-facing gateway that is compromised could impersonate every agent behind it.
- **Gateway-held per-agent state, or a gateway mesh across the internet.** Rejected: membership in an Erlang cluster is full control of every member, and per-agent state at the gateway breaks free gateway choice. Fleet-level state any gateway could rebuild is allowed (conflict 5).
- **A per-session key between agent and server, with a MAC on every message, for D5.** Rejected: it does not survive a command sent by another server or a result redelivered through another gateway, and it proves nothing to a third party (D5).
- **The suggested-gateway list inside the GOAWAY frame, for D11.** Rejected: GOAWAY debug data carries no meaning by RFC 9113, and the agent's gRPC stack does not expose it.
- **OTP `ssl` as the default.** Rejected by the owner, on the measured memory and handshake rate. It is kept as the fallback and as the reference the shared test suite compares against.

## Consequences

- The release that ships wave 2 breaks every existing agent-to-gateway deployment: new port, new certificates, agents re-enroll. This is acceptable only because there are no production customers at the time of writing (2026-10-30); wave 2 re-checks this before it merges, and if a pilot runs agents through a gateway the upgrade note becomes a merge gate.
- Wave 2 ships with an upgrade section in `docs/user-manual/upgrading.md` (the new enrollment port and its firewall rule; the upgrade order server, then gateway, then agents; re-enrollment and its prerequisites; roll-forward), a changelog fragment marked Breaking, and an update to `docs/user-manual/gateway.md`'s "Moving the agent edge to mutual TLS".
- The CA signs far more often: each agent renews every 12 hours instead of about every eight months. At 1.2 million agents that is about 28 signatures per second, around the clock, before any mass re-enrolment. Its signing path, its `ca_issued` table and its CRL size must be measured before wave 2, not after.
- The gateway gains C code that faces the internet. The fuzzing, ASan and advisory-tracking requirements in D8 are permanent.
- `docs/pki-architecture.md`, `docs/user-manual/gateway.md`, the reference composes, the compose wizard and the agent installer all change with waves 1, 2 and 4.

## Open questions

Resolved in wave 0 (2026-10-29): the SPIFFE trust domain (D3), D5's scope, and whether the CRL needs a delta or Bloom-filtered form (it does not with 24-hour leaves; D7).

- **For wave 2:** whether to move kTLS handshakes out of the Erlang VM, so a memory-safety bug costs only the handshakes in flight rather than the gateway. No project surveyed runs a process per handshake; the form to measure is a small pool of handshake OS processes that hand the established socket and its kTLS state back to the gateway.
- **For wave 1:** checking a customer intermediate's revocation: the leaf only, or the customer's root CRL as well (D7).
- **For wave 2:** the TLS version on the main port and, if TLS 1.3, the KeyUpdate policy (D8).
- The ephemeral-port limit on load generators for wave 7: one source address to one gateway port gives about 16,000 connections on macOS defaults.
- **For wave 2:** whether the direct agent-to-server port of single-server installs gets the same enrollment and main port split (D2).
- **For wave 1:** whether the owner accepts that CRL freshness depends every 15 minutes on the CA key, a Postgres write and the leader, or CRL signing is decoupled (D7).
- **For wave 1:** whether a default install gains an issuing intermediate under the Yuzu root, so a mass revocation is not a root rotation (D7).
- **For wave 2:** how an agent learns that a server's signing key is revoked (D5).
- **For wave 5:** how the server that owns an agent's stream learns of a revocation made on another server (D7, D12).
- **Not yet named:** which wave removes the #4669 cluster-affinity admission check (conflict 1).
