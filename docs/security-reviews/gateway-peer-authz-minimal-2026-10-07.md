# Security review: gateway-upstream peer authorization (minimal design)

**Date:** 2026-10-07
**Change:** the gateway-upstream gRPC service (`GatewayUpstream`, five RPCs) is registered only
behind a guard that admits a caller only if its transport-authenticated leaf certificate is pinned
by SPKI SHA-256, lists `serverAuth` and is inside its validity window. Pins are fixed at server
boot. The server refuses to start unless authorization resolves (a pin, the automatic
default-certificate pin, or an explicit acknowledgement).
**Base:** `origin/dev` at `70cb9e70e`
**Branch:** `fix/gateway-peer-authz-minimal`
**Operator guide:** [Gateway upstream peer authorization](../user-manual/server-admin.md#gateway-upstream-peer-authorization);
upgrade steps: [Upgrading](../user-manual/upgrading.md).
**Purpose of this record:** state the threat model, the decision, what was deliberately left out
and why, and what remains open, so that the omitted mechanisms are not re-added by default and not
mistaken for oversights. It is a decision record, not a design proposal.

## Provenance and limits of this record

- It was first written while the code commits of this change (certificate/pin/policy, guard, boot
  resolution and wiring) were being built in parallel, from the agreed plan and from the earlier
  reference implementation (branch `fix/gateway-peer-authz-pr1`, tip `36eb970e6`), which the new code
  reuses with revocation and reload removed. It was then reconciled by reading against the landed
  sources of this change (pin set, guard, boot resolution and wiring, deploy files, alert rules and
  the shell tests). Statements about existing code cite `origin/dev` `70cb9e70e`. A reviewer should
  still check each behavioural claim here against the final code; a claim that disagrees with that
  code is a defect in this record.
- Nothing here was run: no build, test, promtool, compose, installer or governance run is claimed
  by this document, and the reconciliation was a reading of the final sources, not a run. The review inputs (a security consult on the reference implementation, two
  independent consults on the minimal design, and a plan review) were read-only analyses of source;
  every finding they report is code-derived, not experimentally reproduced.

## The gap

The gateway-upstream service authenticated callers only by TLS client-certificate membership of the
install CA (or by the network boundary on a plaintext listener). Reading `origin/dev`:

- The server builds one `grpc::ServerBuilder` and registers the agent service, the management
  service and the gateway-upstream service on it (`server/core/src/server.cpp:8219-8228`). A gRPC
  service registered on a builder is served on every port the builder listens on, so the
  gateway-upstream service is reachable on the agent port (`--listen`, default 50051) and the
  management port as well as on `--gateway-upstream`.
- On the generated default certificates the agent listener is built request-but-not-require
  (`require_client_cert = !cfg_.using_default_agent_certs`, `server.cpp:8115-8121`) so that an
  unenrolled agent can bootstrap. A caller with no client certificate therefore reaches the
  gateway-upstream service on that port. The management and gateway-upstream listeners are strict
  (`server.cpp:8139-8160`), but strict means "signed by the install CA": an agent leaf passes.
- `gateway_service_impl.cpp` performs no caller check; it extracts the peer IP only
  (`:358`, `:740`). After its enrollment checks, `ProxyRegister` records the caller's IP as a
  trusted gateway peer (`registry_.note_trusted_gateway_peer`, `:740`), and the agent service uses
  that set under `--gateway-mode` to relax the Register/Subscribe peer-IP binding for that address
  (`agent_service_impl.cpp:1013`, the #826 binding).

This is exposure rather than a demonstrated end-to-end exploit: reaching the RPCs is shown by the
code; what a given caller can then achieve depends on the request contents and the enrollment
checks the handler applies. The derived severity used for planning was CRITICAL, likely: the
authorization control is absent (impact class I1) and the default shipped configuration exposes it
to unauthenticated callers (exposure E1).

## Threat model

| Actor | Capability assumed | What the control does about it |
|---|---|---|
| Network caller with no certificate, reaching the agent port of a default-certificate install | Can open a TLS connection to `--listen` | Refused as `not_authenticated`; no handler runs. |
| Holder of a CA-issued agent leaf (an enrolled or compromised agent, including one in a container) | Presents a valid leaf signed by the install CA, `clientAuth` only | Refused as `no_server_auth_eku` before the pin is consulted, and also not pinned. |
| Holder of an operator-CA agent leaf that happens to carry `serverAuth` | Valid leaf under the operator's own CA | Refused as `not_pinned` unless its key was pinned. The `serverAuth` requirement is a safeguard, not a classifier: it does not distinguish a gateway from every such leaf, so the pin is the identity. |
| Reader of the gateway private key | Can present the genuine pinned credential | Not stopped by the pin. Handled by key custody (below) and, after exposure, by replacing the key and withdrawing its pin. |
| Gateway with an expired certificate on a long-lived connection | The handshake validated the certificate once | Refused per call as `outside_validity` once the certificate expires. |
| Compromised pinned gateway | Holds the gateway key legitimately | Out of scope: the pin says WHO is calling, not WHAT it may assert. Per-gateway scoping of relayed agent identities (#1292) is the remediation and is unchanged. |
| Operator misconfiguration | Wrong, missing or contradictory pins or acknowledgement | Refuse-to-start before any port binds, with a message naming the flag; no fallback from a broken explicit source to the automatic pin. |

Key custody is part of the control. The pin authorizes exactly one key, so the people and
processes that can read it decide who can act as a gateway. At the base, the reference gateway
compose mounted the whole certificate volume read-only into the agent container
(`deploy/docker/docker-compose.reference-gateway.yml:130`), the agent image places its user in group
`yuzu-pki` (gid 2000, `deploy/docker/Dockerfile.agent:64-68`), and the server group-shares
`default-gateway.key` with mode 0640 for that group (`server/core/src/default_certs.cpp:90-94`).
A read-only mount still permits reading the key, so a compromised agent container could present the
genuine pinned gateway credential. The compose change that mounts only the public CA certificate
into the agent container (a one-shot `ca-export` service filling a `ca-public` volume) is therefore
part of this fix, not an extra: dropping it leaves the control defeatable by the actor class it
exists to stop (derived CRITICAL in the plan review).

## The decision

1. **Guard.** One wrapper service is the sole production registration of the gateway-upstream
   service. Each of the five RPCs calls the pure policy function before delegating. Deny is gRPC
   `UNAUTHENTICATED` with one fixed message; the reason is never sent to the caller. Null context,
   an unauthenticated transport, a missing certificate or any exception during the decision denies.
   Because the guard wraps the service, it covers every port the shared builder serves, including the
   request-not-require agent port.
2. **Policy.** Allow only when the leaf certificate: parses; lists `serverAuth`; has a public key
   whose SHA-256 over the full SubjectPublicKeyInfo DER is in the pin set; and is inside its
   validity window at the time of the call (5 minutes of leeway before `notBefore`, strict expiry).
   Evidence comes from gRPC's authenticated leaf, never from request metadata, a supplied PEM, the
   subject, the issuer or the chain root. The reason set is closed at eight values
   (`null_context`, `not_authenticated`, `no_cert`, `bad_cert`, `no_server_auth_eku`, `not_pinned`,
   `outside_validity`, `internal_error`).
3. **Pins are fixed at boot.** Sources: `--gateway-peer-pin`, `--gateway-peer-pin-file` (read once),
   or the automatic pin of `default-gateway.pem`, applied only when the gRPC listener credentials
   are the generated default files (never merely because HTTPS is on defaults). Explicit pins replace
   the automatic pin. Any malformed, missing, unreadable or empty explicit source refuses to start.
4. **Refuse unless authorized.** A TLS server with a client CA and a pin set enforces. `--no-tls`
   is not an acknowledgement. Operator certificates with no pin refuse. `--insecure-gateway-peer`
   (env `YUZU_INSECURE_GATEWAY_PEER`) is the explicit acknowledgement; it is refused together with an
   explicit pin, disables the guard on every port, and leaves a boot error line, a boot audit row
   (`server.gateway_peer_authz_disabled`) and a mode gauge.
5. **Evidence, kept small.** `yuzu_server_gateway_peer_denied_total{rpc,reason}` (pre-seeded, 5 by 8
   series), a log line, a bounded audit row only for peers whose key hash is known, the mode gauge,
   and two alerts (sustained denials that are not anonymous refusals; acknowledged-insecure mode on a TLS
   server with a client CA). Anonymous refusals are counter and log only, the same split the OTA
   `no_client_identity` rejection already makes (`docs/user-manual/audit-log.md`,
   `session.ota_identity_rejected`), recorded in `docs/observability-conventions.md` so that the
   convention's attributable-denial rule is not read as violated.

## What was left out, and why

An earlier implementation of this fix (about 16.7 thousand added lines over 103 files; 12 thousand
in server and tests, 2.7 thousand in the Erlang gateway) additionally carried a pin-file reload with
a freshness lifetime, a CA-store revocation check on the gateway peer, and an Erlang-side
reconciliation after a refusal. Roughly 60 percent of that size, and all of the Erlang, served those
three mechanisms. None of them is needed to close the gap above, and each added review surface of
its own. The code remains on backup branches; this change does not depend on it.

| Left out | What it was for | Why it is not here |
|---|---|---|
| Pin-file reload every 15 s, freshness lifetime, bounded waiter cap, stale-view gauges | Rotate pins without a restart | Restart-to-rotate is coherent and, for HA, a rolling restart with the union of old and new pins is documented. The reload path read a file on a gRPC worker, so a hung mount could strand a worker per interval (a review finding, later bounded by a single-flight read and a waiter cap), needed a freshness window so a stuck reader could not extend a withdrawn pin, and generated a large share of the review findings. With no reload there is no runtime transition from refuse to accept except a restart. |
| Revocation check on the gateway peer through the CA store | Make revoking a gateway certificate take effect | Serial-scoped revocation has different semantics from pin withdrawal (a certificate reissued over the same key keeps matching its pin), it tied every admitted RPC to the shared Postgres pool, and it needed the certificate-recognition module. Withdrawal is "remove the pin and restart every serving replica", stated plainly in the operator guide. |
| Erlang reconciliation, parking and refusal retention after status 16 | After a refusal window, repair the placement of sessions whose CONNECTED notice was refused | With no pin reload the server never flips from refuse to accept without a restart. The mechanism itself needed repeated review rounds: a read-only consult of an earlier revision found a state in which a transient replay failure followed by a later success left an unrepaired session with no retained obligation, which later revisions addressed with more retained state. It belongs to the gateway workstream, which owns `gateway/` and is changing it now. |
| Runtime pin-change audit row, pin gauges, reload alerts, recognition-module reads | Observe the above | The transitions they observe no longer exist. The boot-time acknowledged-insecure row and mode gauge are kept. |
| Windows installer pin parser and wizard page (about 430 lines of Pascal) | Validate a pin file in the installer | The server validates at start. The installer instead stores the pin where it survives (see below) and does not parse it. |
| Agent certificate standing, `--agent-unrecorded-mode`, Subscribe revalidation | A separate threat on the agent path | Separate threat, separate change. |

Nothing under `gateway/`, no `*gateway-sys.config`, and not `docs/user-manual/gateway.md`,
`docs/erlang-gateway-build.md` or `docs/grafana/README.md` is touched, because the gateway workstream
owns them concurrently. Guidance that earlier lived in sys.config comments is in the operator guide.

## Corrections adopted from review

Two independent consults and a plan review of the minimal design (all read-only, code-derived)
corrected the first written design in these ways, each of which is part of this change:

1. **Keep the key-custody fix** (compose mounts only the public CA certificate into the agent).
2. **Keep the per-call validity check.** The handshake checks validity once per connection; the
   check is small, and it is the one runtime refuse-to-admit flip that needs no server restart
   (expiry followed by a same-key renewal), so the runbook names it.
3. **Keep the audit row for authenticated peers, bounded**, and make anonymous refusals counter and
   log only with the convention sentence written down.
4. **Windows installer durability.** The installer rebuilds the service command line from its own
   state on every run (`deploy/packaging/windows/yuzu-server.iss`, `GetServiceArgs`), so a flag
   appended by hand disappears at the next upgrade, and `/GATEWAY` is re-read each run. The change
   adopts a storage convention without a parser: the pin lives at `certs\gateway-peer-pin`,
   `--gateway-peer-pin-file` is passed whenever gateway mode is selected, TLS is not skipped and that
   file exists, `/GATEWAY` with `/NOTLS` adds the acknowledgement (and no pin file, which the server
   would refuse together with it), and an install that would start gateway mode on operator gRPC
   certificates with no pin is refused before anything changes.
5. **Replace "restart recovers automatically" with a runbook.** The unchanged gateway logs a failed
   `NotifyStreamStatus` and drops it (`gateway/apps/yuzu_gw/src/yuzu_gw_upstream.erl:335-343`), and
   heartbeats for a session the server already knows are acknowledged, so a session whose CONNECTED
   notice was refused can stay unplaced after authorization is restored. The runbook is: restore the
   pins or credentials, restart every serving replica, then restart the gateway nodes.
6. **Acknowledgement semantics.** The acknowledgement is contradictory only with EXPLICIT pins, it
   suppresses the automatic pin, and it disables the guard on every port.
7. **Complete the plaintext list.** Every rig and compose that runs `--gateway-upstream` with
   `--no-tls` carries the acknowledgement, and the upgrade note lists them.
8. **Honest scope.** The security-hardening guide states what the service exposed before.

One further simplification from the plan review: the runtime `NoPins` reason is dropped. The policy takes an
immutable pin set that cannot be empty by construction, and boot refuses an empty set.

## Residual risks and known limits

- **Restart to rotate or withdraw.** Pins change only at boot. HA rotation is a rolling restart with
  the union of old and new pins on every replica. During a mixed-version window an old replica has no
  guard and admits calls a new replica refuses.
- **No in-band revocation of a gateway key.** Revoking a certificate serial does not remove a key
  pin. A compromised key must be replaced and its pin removed from every replica; a copied key stays
  valid until then.
- **After a refusal window the gateway must be restarted** to repair stream placement, because a
  refused `NotifyStreamStatus` is never retried by the gateway. This stays true after the in-flight
  gateway work lands unless that work adds general worker-failure retry for it.
- **Pin identifies, does not scope.** A compromised pinned gateway can still relay another agent's
  identity (R-5 in `docs/security-reviews/pki-pr5-gateway-tls.md`; per-gateway scoping, #1292).
- **Key custody is only as good as its deployment.** Anyone in `--cert-group` holds the gateway key
  on the generated defaults; the server warns at boot when `--cert-group` is set while the default
  gateway key is in use. Production installs should use
  a gateway-only certificate with a 0600 key, pinned explicitly.
- **Breaking for custom certificates.** Bring-your-own gateway certificate installs must supply a pin
  or acknowledge before upgrading; the Linux unit passes `--gateway-upstream` unconditionally, so an
  own-certificate install that runs no gateway refuses to start until it omits the flag or pins.
- **CI does not exercise a pinned gateway hop end to end.** The integration rig
  (`scripts/integration-test.sh`) keeps the acknowledgement in its `--tls` branch, and no workflow
  under `.github/` invokes that script. The guard is exercised by unit tests over a real mTLS
  harness on both listener modes, not by the rig.
- **Two reasons are covered at the predicate level only.** Over a real gRPC connection the guard's
  wire tests produce `not_authenticated`, `no_server_auth_eku`, `not_pinned` and `outside_validity`
  (and `null_context` by a direct call with no context). `no_cert` and `bad_cert` could not be
  produced over a real connection in that harness; they are covered only by the policy-function
  table (`tests/unit/server/test_gateway_peer_policy.cpp`) and by the label and audit-eligibility
  tests, so a wiring fault that made them unreachable or mis-attributed over the wire would not be
  caught by a wire test.
- **The Windows installer change is not compiled.** `deploy/packaging/windows/yuzu-server.iss` was
  edited on a Linux host with no Inno Setup compiler. It needs a compile and a silent-install check
  (`/GATEWAY` with and without `/NOTLS`, with and without a pin, and an upgrade over an install
  carrying operator certificates) on a Windows host before it is relied on.
- **No pin-file permission or ownership warning.** The earlier implementation warned when a pin file
  was a symbolic link, writable by group or others, or owned by an unexpected user. This one does
  not: the server reads the file once, bounded, and the operator guide tells the administrator to
  protect it. Whoever can write the file at boot decides which gateway key is admitted.
- **TLS session resumption.** See the next section; it is a question for the independent review.
- **Acknowledged mode is a deliberate off switch.** It disables the guard on every port and is
  detectable (error line, audit row, gauge, alert on TLS servers with a client CA) but not preventable.
- **Anonymous refusals have no audit row.** They are counter and log only.
- **Rollback loses the control.** The previous binary has no guard; rolling back is a recorded risk
  acceptance, and the new flags must be removed before a binary rollback (an older binary rejects an
  unknown flag but ignores an unknown environment variable).

## TLS session resumption

What the guard judges. The guard judges the peer certificate that gRPC reports for the call
(`x509_pem_cert` in the auth context, `grpc_peer_evidence.hpp`). It cannot tell whether that
certificate was presented in this connection's handshake or restored from a resumed TLS session, and
gRPC's public API does not expose resumption.

What the test showed. `tests/unit/server/test_gateway_peer_guard.cpp`, test case "two sequential
channels sharing an LRU session cache give identical evidence and identical decisions" (tags
`[session]`), opens two sequential client channels with an LRU session cache attached
(`GRPC_SSL_SESSION_CACHE_ARG`) for a pinned and for an unpinned gateway leaf, on both listener modes.
In a first draft of that test one cache was shared by the pinned and the unpinned client identity, and
the unpinned leaf was then admitted. That is consistent with the unpinned identity's channel resuming
the pinned identity's cached session, so that the guard judged the certificate the session restored;
resumption itself was not separately confirmed, because it is not observable from gRPC's public API
(the test's own comment says so). The test was then changed to one cache per client identity. The
first-draft observation is recorded only in that test comment; no test pins it.

What it means, stated without overclaiming. The shared cache was in one process, set up by the test
harness. A client channel can only reuse another identity's cached session if it holds that
identity's session state (the ticket and its secret), so the exposure requires the pinned peer's
own session state, which is equivalent to holding that peer's session secret. It does not require the
gateway's private key, so it is a weaker credential than the key, but it is the pinned peer's own
state and not something a network caller who merely reaches the port holds. How long such a session
stays resumable is bounded by the OpenSSL server context's session lifetime, which was not measured
here.

What bounds it on the server. In gRPC 1.76's TSI server factory (`src/core/tsi/ssl_transport_security.cc`,
read in the vcpkg build tree, around lines 2750 to 2770) the server sets a session-id context and
installs a session-ticket key only when one is supplied through the TSI options; nothing in the gRPC
core tree supplies one, and this server configures none, so ticket keys are the ones OpenSSL generates
for each server context, per process. The only pin-withdrawal path in this design is a restart, which
therefore invalidates every ticket issued before it. This is read from source, not tested here.

Question for the independent review. Is it acceptable that admission is decided on the certificate
gRPC reports for the call, without knowing whether it was presented fresh in this handshake or
restored from a resumed session, given that reuse requires the pinned peer's own session state and a
restart invalidates it? If not, what binds a decision to the current handshake through gRPC's public
API (or is a server-side option to disable ticket issuance on the gateway-upstream listener required)?

## Deferred follow-ups

Each is a separate decision; none is a prerequisite for this change.

1. Pin-file reload with a freshness lifetime (restart-free rotation): only if operators demand it;
   a reviewed implementation exists on a backup branch.
2. Gateway-peer revocation through the CA store: needs the recognition module and a store read on the
   request path, and semantics that differ from pin withdrawal.
3. Gateway-side reconciliation after status 16 (`yuzu_gw_upstream.erl`): belongs to the gateway
   workstream; coordinate with its deferred worker-failure retry.
4. Agent certificate standing, `--agent-unrecorded-mode` and Subscribe revalidation.
5. Windows installer pin parser and full wizard page; validation stays server-side meanwhile.
6. Integration rig: run the `--tls` branch with a real pinned gateway leaf instead of the
   acknowledgement, so CI exercises the hop.
7. Per-gateway scoping of relayed agent identities (#1292).
8. An info alert on unauthenticated probes, and a per-port deny of the gateway-upstream service on the
   agent port (which would need a second gRPC server): both reduce noise or surface; neither is
   needed for the control.
9. Chisel images and an ADR note that the key-bearing volume is never mounted into agents
   (documentation only).

## Where this is enforced

- Routed-concern row "Gateway-upstream peer authorization" in
  `.claude/routed-concerns-security-posture.md` carries the catastrophic-if-violated clauses and the
  review triggers (guard sources, the `RegisterService` site in `server.cpp`, the shell tests, and any
  new use of `--insecure-gateway-peer` or `YUZU_INSECURE_GATEWAY_PEER`). Re-adding reload, freshness
  or a revocation read on this path requires re-opening this record first.
- A lexical shell gate (a Meson test in the `docs` suite) fails if the gateway-upstream service is
  registered other than through the guard or if the registration count changes; a boot-refusal shell
  test (`tests/shell/test_gateway_peer_boot_refusal.sh`, a step in `.github/workflows/ci.yml`; it
  needs the server binary and Postgres) exercises the refusal and acknowledgement rows against the
  real binary.
