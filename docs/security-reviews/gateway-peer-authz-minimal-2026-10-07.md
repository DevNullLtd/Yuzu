# Security review: gateway-upstream peer authorization (minimal design)

**Date:** 2026-10-07
**Subject:** the gateway-upstream gRPC service (`GatewayUpstream`, five RPCs) is registered only
behind a guard that admits a caller only if its transport-authenticated leaf certificate is pinned
by SPKI SHA-256, lists `serverAuth` and is inside its validity window. Pins are fixed at server
boot. The server refuses to start unless authorization resolves (a pin, the automatic
default-certificate pin, or an explicit acknowledgement).
**Base:** `origin/dev` at `056f01a20`
**Operator guide:** [Gateway upstream peer authorization](../user-manual/server-admin.md#gateway-upstream-peer-authorization);
upgrade steps: [Upgrading](../user-manual/upgrading.md).
**Purpose of this record:** state the threat model, the decision, what was deliberately left out
and why, and what remains open, so that the omitted mechanisms are not re-added by default and not
mistaken for oversights. It is a decision record, not a design proposal.

## Provenance and limits of this record

What this record claims, and what it does not.

- **Review.** The design and code were reviewed by the Yuzu governance pipeline: review agents
  run from the authoring session. That is **not independent review**. No external review has occurred, and no
  external reviewer has adjudicated the TLS session-resumption question below.
- **Design consults before implementation.** Read-only analyses of source, run before the code
  was written: two consults on the minimal design, a plan review, and a security consult on an
  earlier, larger design that was withdrawn as too complex to review (its relation to this one is
  under "What was left out"). Every finding they report is code-derived, not experimentally
  reproduced.
- **Test runs.** Linux: the `[gateway_peer]` tests, 104 cases with 1909 assertions, and the full
  server suite, 8824 cases (8821 passed, 3 skipped), at the code before the review-fix round.
  macOS: the full test binary, 8830 cases (8825 passed, 5 skipped), and `[gateway_peer]`, 104
  cases with 1907 assertions, at an earlier tip. Windows: `[gateway_peer]`, 104 cases with 1909
  assertions. These counts predate the review-fix rounds, which add tests, so re-run before
  quoting them; the final counts at the shipped tip are recorded in the governance run record committed with this change. [TO BE FILLED BY LEAD: counts]
- **Installer.** `deploy/packaging/windows/yuzu-server.iss` was edited on a Linux host. It was then
  compiled with Inno Setup 6.7.3 and silent-installed on a Windows 11 test host: about 55
  silent-install cases (including upgrade, refusal and uninstall cases) plus server command-line
  runs, at a pre-rebase tip, the installer file being unchanged between that run and the start of
  the review-fix round. The review-fix round then edited the installer (the refusal of `/NOTLS`
  together with a pin, the wizard-path refusal wording, header comments); those edits are not
  covered by those runs. Not tested at all: starting the service under the Windows service
  manager, because the server binary does not implement the service control protocol
  (pre-existing; open issue #1835, "Windows server binary has the identical SCM control-protocol
  defect as #1822 (agent)", which prevents the installed service from starting under the Windows
  service manager), and the interactive wizard path. Install behaviour on macOS and Linux does not apply: the installer is
  Windows-only.
- **Citations.** Statements about existing code cite `origin/dev` at `056f01a20` by symbol. The
  line numbers in "The gap" were read at an earlier base and can be a few lines off (for example
  the `RegisterService` calls are at `server.cpp:8221` to `8228` on `056f01a20`). A reviewer should
  check each behavioural claim here against the final code; a claim that disagrees with that code
  is a defect in this record.

## The gap

The gateway-upstream service authenticated callers only by TLS client-certificate membership of the
install CA (or by the network boundary on a plaintext listener). Reading `origin/dev`:

- The server builds one `grpc::ServerBuilder` and registers the agent service, the management
  service and the gateway-upstream service on it (`server/core/src/server.cpp:8221-8228`). A gRPC
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
| Gateway with an expired certificate on a long-lived connection | The handshake validated the certificate once | Refused per call as `outside_validity` once the certificate expires (see "The expiry cliff" under the residual risks: renewal takes effect only after the gateway redials). |
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
part of the control, not an extra: dropping it leaves the control defeatable by the actor class it
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
   validity window at the time of the call (the window opens 5 minutes before `notBefore`, a leeway that applies to this per-call check only, and a call is denied when the current time, in whole seconds, is later than `notAfter`).
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
   and alerts: sustained denials that are not anonymous refusals (warning), the gateway's own
   heartbeat being refused (critical), acknowledged-insecure mode on a TLS server with a client CA,
   and two gateway-side rules (upstream status 16 and upstream TLS handshake failures, which only
   fire where the gateway's metrics are scraped). Anonymous refusals are counter and log only, the same split the OTA
   `no_client_identity` rejection already makes (`docs/user-manual/audit-log.md`,
   `session.ota_identity_rejected`), recorded in `docs/observability-conventions.md` so that the
   convention's attributable-denial rule is not read as violated.

## What was left out, and why

An earlier, larger design was withdrawn as too complex to review (more than twice the size of this
one, including changes to the Erlang gateway). It additionally carried a pin-file reload with a
freshness lifetime, a CA-store revocation check on the gateway peer, and an Erlang-side
reconciliation after a refusal. Most of its size, and all of its Erlang, served those three
mechanisms. None of them is needed to close the gap above, and each added review surface of its
own. This design does not depend on that one, and nothing from it is claimed as reviewed here.

| Left out | What it was for | Why it is not here |
|---|---|---|
| Pin-file reload every 15 s, freshness lifetime, bounded waiter cap, stale-view gauges | Rotate pins without a restart | Restart-to-rotate is coherent and, for HA, a rolling restart with the union of old and new pins is documented. The reload path read a file on a gRPC worker, so a hung mount could strand a worker per interval (a review finding, later bounded by a single-flight read and a waiter cap), needed a freshness window so a stuck reader could not extend a withdrawn pin, and generated a large share of the review findings. With no reload there is no runtime transition from refuse to accept except a restart. |
| Revocation check on the gateway peer through the CA store | Make revoking a gateway certificate take effect | Serial-scoped revocation has different semantics from pin withdrawal (a certificate reissued over the same key keeps matching its pin), it tied every admitted RPC to the shared Postgres pool, and it needed the certificate-recognition module. Withdrawal is "remove the pin and restart every serving replica", stated plainly in the operator guide. |
| Erlang reconciliation, parking and refusal retention after status 16 | After a refusal window, repair the placement of sessions whose CONNECTED notice was refused | With no pin reload the server never flips from refuse to accept without a restart. The mechanism itself needed repeated review rounds: a read-only consult of an earlier revision found a state in which a transient replay failure followed by a later success left an unrepaired session with no retained obligation, which later revisions addressed with more retained state. It belongs to the gateway workstream, which owns `gateway/`. |
| Runtime pin-change audit row, pin gauges, reload alerts, recognition-module reads | Observe the above | The transitions they observe no longer exist. The boot-time acknowledged-insecure row and mode gauge are kept. |
| Windows installer pin parser and wizard page (about 430 lines of Pascal) | Validate a pin file in the installer | The server validates at start. The installer instead stores the pin where it survives (see below). It checks only that a `/GATEWAY_PEER_PIN` value is 64 hexadecimal characters and that a pin file exists, is not empty and has no NUL byte; it never parses a pin file. |
| Agent certificate standing, `--agent-unrecorded-mode`, Subscribe revalidation | A separate threat on the agent path | Separate threat, separate change. |

Nothing under `gateway/`, no `*gateway-sys.config`, and not `docs/user-manual/gateway.md`,
`docs/erlang-gateway-build.md` or `docs/grafana/README.md` is touched, because the gateway workstream
owns them. Guidance that earlier lived in sys.config comments is in the operator guide. The
consequence is listed under "Deferred follow-ups": some prose in those reserved files is now stale.

## Corrections adopted from review

Two design consults and a plan review of the minimal design (all read-only, code-derived; not
independent review in the sense of "Provenance and limits") corrected the first written design in
these ways, each of which is part of the design as built:

1. **Keep the key-custody fix** (compose mounts only the public CA certificate into the agent).
2. **Keep the per-call validity check.** The handshake checks validity once per connection; the
   check is small, and it is the one runtime refuse-to-admit flip that needs no server restart
   (a certificate that expires on an open connection). It has a consequence the runbook names:
   renewal is picked up only when the gateway redials (see "The expiry cliff").
3. **Keep the audit row for authenticated peers, bounded**, and make anonymous refusals counter and
   log only with the convention sentence written down.
4. **Windows installer durability.** The installer rebuilds the service command line from its own
   state on every run (`deploy/packaging/windows/yuzu-server.iss`, `GetServiceArgs`), so a flag
   appended by hand disappears at the next upgrade, and `/GATEWAY` is re-read each run. The change
   adopts a storage convention without a pin parser (only cheap checks): the pin lives at `certs\gateway-peer-pin`,
   `--gateway-peer-pin-file` is passed whenever gateway mode is selected, TLS is not skipped and that
   file exists, `/GATEWAY` with `/NOTLS` adds the acknowledgement (and no pin file, which the server
   would refuse together with it), and an install that would start gateway mode on operator gRPC
   certificates with no pin is refused before anything changes.
5. **Replace "restart recovers automatically" with a runbook.** The unchanged gateway logs a failed
   `NotifyStreamStatus` and drops it (`gateway/apps/yuzu_gw/src/yuzu_gw_upstream.erl:335-343`), and
   heartbeats for a session the server already knows are acknowledged, so a session whose CONNECTED
   notice was refused can stay unplaced after authorization is restored. The runbook does **not**
   gate a gateway restart on the circuit state, because a rule of the form "restart the gateway
   only if the circuit is closed, wait if it is open" cannot be satisfied when the cause is on the
   gateway side (an expired certificate, a rotated key, a renamed default marker): every status 16
   on a registration or inventory call counts toward the breaker, the gateway never redials by
   itself (status 16 is an RPC result), so the circuit stays open and waiting never ends. Nor does
   it treat agreeing connected-agent counts as proof of recovery: the server's
   `yuzu_agents_connected` counts registration, while placement is set separately by
   `NotifyStreamStatus`, so an agent whose CONNECTED notice was refused or dropped is counted but
   unreachable for commands. The runbook has three cause classes. **A**, the cause was on the server
   side (a pin, an acknowledgement, other server configuration): restart the serving replicas, do
   not restart the gateways first unless the placement check fails, and verify convergence
   (`sum(yuzu_gw_agents_current) - sum(yuzu_agents_connected{job="yuzu-server"})`, summed across all
   replicas), placement (no rise in the raw notify error and drop counters, and a read-only command to a sample
   agent returns a result) as separate checks. **B**, the cause is on the gateway side: the gateway presents its
   current files only when it redials, and a server restart or any dropped connection forces a
   redial, so first check whether it already has (the raw denial counters have stopped rising, no
   new `spki=` denial lines, and the configured certificate file has the expected SPKI prefix),
   allow about 2 minutes after the files change for the Erlang ssl PEM cache, and restart that
   gateway node, one at a time, only if denials continue, whatever the circuit state. A same-key
   renewal needs no server restart, which is required only when server configuration changed.
   **C**, placement loss suspected after a refusal window: restart the agent service on the
   specific unreachable agents (the observed fix in `docs/user-manual/gateway.md`), and restart the
   gateway node only if many agents behind one node are affected and A's verification still fails
   after the timing allowances. Every gateway restart is conditional and carries the agent-side
   caveat, because `docs/user-manual/gateway.md` ("What
   happens when the server restarts") records that a gateway restart leaves released agents wedged
   on agent builds without the #5183 fix (in no release yet). Redialling is inferred from reading
   the grpcbox code (the certificate and key are file paths in the channel's TLS options, and a
   channel reconnects lazily after its connection process dies) and was not tested. The certificate
   cache caveat (a redial can present the previous certificate for about 2 minutes) was measured by
   a reviewer on OTP 28.4.2 with a stub, not on a Yuzu gateway. What a refusal
   window costs is listed in the operator guide's incident runbook.
6. **Acknowledgement semantics.** The acknowledgement is contradictory only with EXPLICIT pins, it
   suppresses the automatic pin, and it disables the guard on every port.
7. **Complete the plaintext list.** Every rig and compose that runs `--gateway-upstream` with
   `--no-tls` carries the acknowledgement, and the upgrade note lists them.
8. **Honest scope.** The security-hardening guide states what the service exposed before.

One further simplification from the plan review: the runtime `NoPins` reason is not present. The policy takes an
immutable pin set that cannot be empty by construction, and boot refuses an empty set.

## Residual risks and known limits

- **Restart to rotate or withdraw.** Pins change only at boot. HA rotation is a rolling restart with
  the union of old and new pins on every replica. During a mixed-version window an old replica has no
  guard and admits calls a new replica refuses.
- **No in-band revocation of a gateway key.** Revoking a certificate serial does not remove a key
  pin. A compromised key must be replaced and its pin removed from every replica; a copied key stays
  valid until then.
- **After a refusal window stream placement may need repair, and the repair depends on where the
  cause was.** A refused `NotifyStreamStatus` is never retried by the unchanged gateway, and
  heartbeats for a session the server already knows trigger no replay. The runbook (see correction
  5 above and the operator guide) has three classes: a server-side cause is fixed by restarting the
  serving replicas, not the gateways, and verified by three separate checks (registration counts
  summed across all replicas, placement, a sample command); a gateway-side cause needs the gateway to redial, which a server restart already forces, so
  that gateway node is restarted, one at a time, only if denials continue; placement loss after a
  refusal window is handled first by restarting the agent service on the unreachable agents, and
  by a gateway restart only as the last resort. A gateway restart is itself costly: on agent builds without
  the #5183 fix (in no release yet) it leaves released agents wedged
  (`docs/user-manual/gateway.md`, "What happens when the server restarts"). What a refusal window
  costs, beyond the unplaced sessions: `ForwardGuardianMessage` frames dropped during the window
  are never replayed; a refused `DISCONNECTED` notice leaves a stale placement; agent `Register`
  calls fail with `INTERNAL` from the first refusal, and those refusals feed the gateway's
  breaker, whose open state turns `/readyz` to 503 and drops stream-status notices; and the
  gateway retries heartbeats every second with a WARN line each time (noise, not a fault). Only
  `ProxyRegister` and `ProxyInventory` results feed the breaker, so the breaker can stay closed
  and `/readyz` can answer 200 while every heartbeat is refused (a window with no registering
  agents). Timing: the 300 s breaker cap applies only if the breaker opened; the unknown-session
  verdict needs the agent's heartbeat to appear in a flush (up to one agent heartbeat interval plus
  one flush); the replay drip is `registration_replay_spacing_ms` (20 ms by default) per agent
  plus RPC time, so 10,000 agents take at least 200 s; and `yuzu_gw_agents_current` is sampled
  every 10 s. While replicas disagree an admit-on-one, deny-on-another pattern can re-arm a
  replay. The timings and the replica pattern are expected from reading the gateway code; they
  were not measured.
- **The expiry cliff.** The guard re-checks validity on every call, so a gateway whose long-lived
  HTTP/2 connection outlives its certificate's `notAfter` is refused with `outside_validity` on
  every call from that moment. Status 16 is an RPC result: the gateway does not redial by itself.
  A renewed certificate, over the same key or a new one, is presented only after the gateway
  redials: a gateway redials after its connection drops (for example when the server restarts) and
  reads its certificate and key from the configured files when it does (inferred from reading the
  grpcbox code, not tested). Plan certificate renewal before `notAfter`, inside a maintenance
  window; after replacing the files, check whether the gateway already redialled and allow about 2
  minutes for the Erlang ssl PEM cache (measured on OTP 28.4.2 with a stub, not on a Yuzu
  gateway), and restart that gateway node, one at a time, only if denials continue and its agents
  can take the disconnect: on agents without the #5183 fix (in no release yet) released agents stay
  wedged afterwards. After `notAfter` the circuit can stay open and waiting does not
  help, because the cause is on the gateway side. The handshake applies no validity
  tolerance; the 5-minute allowance before `notBefore` exists only in the per-call check. A
  connection-age cap, or a gateway-side redial on status 16, would close this; neither exists.
- **A handshake-level lockout has no server-side signal.** A gateway whose certificate lacks
  `clientAuth`, or is not signed by the CA the listener trusts, fails the TLS handshake and never
  reaches the guard, so no `yuzu_server_gateway_peer_denied_total` series moves. The gateway-side
  alert on `yuzu_gw_upstream_tls_handshake_failures_total` covers it once the gateway's metrics
  are scraped.
- **The denial audit write is synchronous.** It runs on the gRPC handler thread and shares the
  audit store's connection pool. It is bounded by the per-key budget: the worst case is 680 rows
  per 10-second window per replica (64 tracked keys times 10 rows is 640, plus one `<reason>|*`
  overflow bucket of 10 rows for each of the 4 audit-eligible reasons, which is 40), up to 1,360
  across a fixed-window boundary, and about 5.9 million rows per day per replica if sustained (it
  needs 64 or more distinct enrolled leaves refused at once). A single leaf produces 86,400 rows
  per day (10 rows per 10 seconds, 1 row per second). A
  degraded Postgres can hold handler threads for the length of an audit write, which is why the
  budget exists. This is a sustained volume ceiling of the audit trail, not of the counter, which
  is complete.
- **The pin set cannot be compared across replicas** except through the pin prefixes in each
  replica's boot log line. A pin file that differs between replicas is a silent divergence until a
  call lands on the wrong replica.
- **A command-line pin makes the environment pins ignored.** `--gateway-peer-pin` on the command
  line takes precedence over `YUZU_GATEWAY_PEER_PINS` entirely (the values are not merged), so
  during a rotation list both pins in the same source.
- **A stale installer pin file replaces the automatic pin.** On Windows the installer passes
  `--gateway-peer-pin-file` for `certs\gateway-peer-pin` whenever the file exists, gateway mode is
  on and TLS is not skipped. After reverting an install to the generated default certificates the
  old file still exists and its pin replaces the automatic pin, so the gateway's generated
  certificate is refused until the file is deleted (`del "%ProgramData%\Yuzu Server\certs\gateway-peer-pin"`,
  then run the installer again).
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
- **Windows installer verification is partial.** See "Provenance and limits of this record" for
  exactly what was compiled and run. In short: the compile and about 55 silent installs predate the
  review-fix round's installer edits; service start under the Windows service manager could not be
  tested (#1835, "Windows server binary has the identical SCM control-protocol defect as #1822
  (agent)"); the interactive wizard was not tested, and it has no pin page, so a pin can be given
  only on the command line.
- **Windows installer behaviour to know.** Re-supplying `/GATEWAY_PEER_PIN` or
  `/GATEWAY_PEER_PIN_FILE` replaces `certs\gateway-peer-pin`; rotation with an overlap needs a
  multi-entry pin file. When the service fails to start the Windows service manager reports 1053,
  7000 or 7009 for every cause, so the reason is in `<install>\logs\yuzu-server.log`. The installer
  fixes the gateway-upstream listen address at `0.0.0.0:50055` and does not emit `--ca-dir`
  (platform default), so two server services on one host collide. A silent `/NOTLS` clears
  `/GRPC_CERT`, `/GRPC_KEY` and `/CA_CERT`, as the wizard does.
- **No pin-file permission or ownership warning.** The server does not warn when a pin file is
  writable by group or others or owned by an unexpected user: it reads the file once, bounded, and
  the operator guide tells the administrator to protect it. Whoever can write the file at boot
  decides which gateway key is admitted.
- **TLS session resumption.** See the next section: the question is open and unadjudicated, and no
  external review has occurred.
- **Acknowledged mode is a deliberate off switch.** It disables the guard on every port and is
  detectable (error line, audit row, gauge, alert on TLS servers with a client CA) but not preventable.
- **Anonymous refusals have no audit row.** They are counter and log only; the rate-limited warning
  carries the transport peer address as `peer=<ip>`, so an operator can find the source.
- **A denied peer's audit principal is unverified.** The row's principal is `gateway-peer:<spki8>`
  and its `principal_role` is `unverified_peer`: the caller failed the pin, so the row does not claim
  it is a gateway (an agent-leaf probe lands here too).
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

What it means, stated without overclaiming. This is the conclusion as reviewed by the governance
pipeline, not an external adjudication. The shared cache was in one process, set up by the test
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

Status: open, unadjudicated; no external review has occurred. The conclusion reached inside the
governance pipeline is that this is acceptable: reuse requires the pinned peer's own session state,
tickets are keyed per process (so a restart invalidates them), and no network caller who merely
reaches the port holds either. The question a reviewer should answer is whether admission may be
decided on the certificate gRPC reports for the call without knowing whether it was presented fresh
in this handshake or restored from a resumed session, and, if not, what binds a decision to the
current handshake through gRPC's public API. Optional hardening, not implemented: disable session
ticket issuance on the gateway-upstream listener.

## Deferred follow-ups

Each is a separate decision; none is a prerequisite for the control.

1. Pin-file reload with a freshness lifetime (restart-free rotation): only if operators demand it;
   the earlier, withdrawn design had one, which is not part of this design, so it would need a
   fresh implementation and review.
2. Gateway-peer revocation through the CA store: needs the recognition module and a store read on the
   request path, and semantics that differ from pin withdrawal.
3. Gateway-side reconciliation after status 16 (`yuzu_gw_upstream.erl`): belongs to the gateway
   workstream; coordinate with its deferred worker-failure retry.
4. Agent certificate standing, `--agent-unrecorded-mode` and Subscribe revalidation.
5. Windows installer pin parser and full wizard page; full validation stays server-side meanwhile (the installer only does the cheap checks described above).
6. Integration rig: run the `--tls` branch with a real pinned gateway leaf instead of the
   acknowledgement, so CI exercises the hop.
7. Per-gateway scoping of relayed agent identities (#1292).
8. An info alert on unauthenticated probes, and a per-port deny of the gateway-upstream service on the
   agent port (which would need a second gRPC server): both reduce noise or surface; neither is
   needed for the control.
9. Chisel images and an ADR note that the key-bearing volume is never mounted into agents
   (documentation only).
10. A connection-age cap on the gateway-upstream listener, or a gateway-side redial on status 16, so
    that a renewed gateway certificate is picked up without any operator action on the gateway
    (the expiry cliff under the residual risks). Neither exists.
11. A `--check-config`-style dry run of the boot resolution, so an upgrade can be checked before the
    restart. It does not exist; operators check the unit, env file and certificate arguments by
    hand (see Upgrading).
12. Prose in the reserved gateway files that could not be edited alongside this control and is now stale. Each
    is a candidate for a follow-up issue, to be filed only on explicit instruction:
    - `docs/user-manual/gateway.md`, the hop table near line 892 (says mutual TLS only; the server
      now also requires a pinned peer or an acknowledgement);
    - `docs/user-manual/gateway.md` near lines 1038 to 1044 (a bare `--gateway-upstream` example,
      which now refuses to start on operator certificates or with `--no-tls`);
    - `docs/user-manual/gateway.md` near lines 1306 to 1309 and the row at line 1102 (both say a gateway
      restart does not help): true for a server-side outage, false when the cause is on the gateway
      side, where the gateway must redial to present its current certificate (cause class B of the
      incident runbook);
    - `docs/user-manual/gateway.md` near lines 1101 and 1102 (the circuit-breaker rows): they do not
      say which refusals feed the breaker. A run of status 16 refusals of `ProxyRegister` (a replay
      registration included) or `ProxyInventory` opens it, because `record_result` in
      `yuzu_gw_upstream.erl` counts any error result of those two paths. Refused `BatchHeartbeat`,
      `NotifyStreamStatus` and `ForwardGuardianMessage` calls do not feed it (the same file calls
      `record_result` on no other path, and `gateway.md` near line 1306 says a heartbeat flush
      never feeds the breaker), so the breaker can stay closed and `/readyz` can answer 200 while
      every heartbeat is refused. When it does open on a gateway-side cause, waiting does not
      close it (the gateway does not redial on status 16), which the "Gateway peer authorization"
      incident runbook in the operator guide covers;
    - `gateway/config/sys.config`, comments near lines 12 and 106 (they say only that the port must
      match `--gateway-upstream`, not that the server must also be given a pin or an
      acknowledgement);
    - `gateway/config/sys.config.prod`, comments near lines 109 to 113, and
      `deploy/docker/reference-gateway-sys.config`, comments near lines 87 to 89 ("replace with
      operator certs if you bring your own" says nothing about the pin requirement that operator
      certificates now bring);
    - `gateway/apps/yuzu_gw/integration_test/yuzu_gw_real_upstream_SUITE.erl`, its header (starts
      the server with `--no-tls` and without `--insecure-gateway-peer`, which the server now
      refuses).

## Where this is enforced

- Routed-concern row "Gateway-upstream peer authorization" in
  `.claude/routed-concerns-security-posture.md` carries the catastrophic-if-violated clauses and the
  review triggers (guard sources, the `RegisterService` site in `server.cpp`, the shell tests, and any
  new use of `--insecure-gateway-peer` or `YUZU_INSECURE_GATEWAY_PEER`). Re-adding reload, freshness
  or a revocation read on this path requires re-opening this record first.
- A lexical Python gate (`tests/test_gateway_peer_registration_lexical.py`, a Meson test in the
  `docs` suite) fails if the gateway-upstream service is registered other than through the guard or
  if the registration count changes; a boot-refusal shell
  test (`tests/shell/test_gateway_peer_boot_refusal.sh`, a step in `.github/workflows/ci.yml`; it
  needs the server binary and Postgres) exercises the refusal and acknowledgement rows against the
  real binary.
