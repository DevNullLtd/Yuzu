# ADR-0069: Gateway transport — an owned gRPC layer over Cowboy and gun, and the overload model

- **Status:** Accepted
- **Date:** 2026-10-16. The decision was taken on 2026-10-09 and is recorded here.
- **Authors:** Nathan Dornbrook
- **Supersedes:** nothing. It is the separate decision that ADR-0066's Consequences anticipated, and that ADR-0066's 2026-10-10 and 2026-10-11 amendments describe as having no ADR number.
- **Related:** ADR-0066 (gRPC stays the permanent transport), ADR-0035 (the server and gateway are Linux-only), ADR-2002 (HA).
  - Issues: #635 (inbound flow control), #5956 (one message per intent: batched dispatch and a single cancel), #5696, #1172, #1293.
  - PR #5695 (the implementation).
- **Threat model:** `docs/security-reviews/gateway-cowboy-edge-2026-10-16.md`.

## Context

The gateway relays between agents and the server. It served its two listeners (agent `:50051`, management `:50063`) and its upstream client (`GatewayUpstream`, `:50055`) with grpcbox over chatterbox.

The fixes the gateway depended on were not in any grpcbox release, for example the auth-reject and late-DATA-after-deadline defects (tsloughter/grpcbox#122, #123). The maintainer did not respond. Staying meant carrying a vendored, patched fork of a gRPC server indefinitely, with three patch sites and an integrity gate. grpcbox and chatterbox also could not be tuned to the load the project is aiming at.

That load is the deciding context:
- **Fleet:** Yuzu must reach **1.2 million connected agents**.
- **Per gateway:** the plan allows up to about a thousand gateways, but **one gateway must support 100,000 agents**.

At that scale the system needs explicit backpressure, bounded mailboxes, let-it-crash isolation, load shedding and overload handling. That applies to the server, the gateway and the agent alike, not to the transport alone.

## Decision

1. **The gateway serves gRPC through a thin layer owned in this repository, over Cowboy and Ranch.**
   - The modules are `gateway/apps/yuzu_gw/src/yuzu_grpc*.erl`, configured under `{yuzu_gw, grpc_listeners}`.
   - The wire protocol and the protobuf contracts are unchanged (ADR-0066).
2. **The gateway's upstream client is its own unary gRPC client over a pool of gun connections.** The modules are `yuzu_grpc_client`, `yuzu_grpc_client_channel` and `yuzu_grpc_client_config`, configured under `{yuzu_gw, upstream_client}`.
3. **grpcbox, chatterbox, hpack, acceptor_pool and gproc leave the gateway entirely**, together with the vendored `gateway/_checkouts/grpcbox` and its integrity check.
4. **The gateway's only third-party dependency for HTTP/2 is Cowboy, gun and cowlib.** No other gRPC framework is adopted.

## Rationale

- **No vendored fork.** Owning a thin layer removes the dependency on an unresponsive upstream. The security-relevant paths are now code this project controls:
  - the management pin check before any handler exists;
  - dropping data after a status;
  - peer and origin attribution.
- **Tunable and modern.** Cowboy exposes the HTTP/2 machinery as options: frame and cancel rates, windows, stream caps, timeouts. It is actively maintained.
- **One HTTP/2 stack in both directions.** gun and Cowboy share cowlib and their maintainers (Nine Nines), so inbound and outbound framing behave the same way and are tuned in one place.
- **A concurrency model the overload work can build on.** The project specifically wanted Cowboy's process per connection, and gun's process per connection across a pool. Those are the building blocks the Erlang community's load-handling practice assumes. Cowboy and gun showed a clear path to stable behaviour under concurrency.

## Alternatives considered

- **Stay on grpcbox and work the fix backlog** (#1172, #1293, #635, #3913, #5175). Rejected: the "small fixes" stayed small only while the project maintained a fork itself, and the stack could not be tuned to the target load.
- **grpcbox upstream master, carrying the unreleased fixes.** Rejected: the same unresponsive-maintainer problem.
- **elixir-grpc** (Cowboy-based). Rejected: it brings the Elixir runtime into an Erlang release.
- **Bluehouse `grpc`** (Erlang, Cowboy 2). Rejected: dormant.
- **QUIC** (msquic/quicer). Withdrawn by ADR-0066.

## The overload model (binding direction)

New work on the server, gateway and agent follows these principles. They are the established Erlang/OTP practice: F. Hébert, *Handling Overload* and *Queues Don't Fix Overload*; *Erlang in Anger*, ch. 3, *Planning for Overload*.

1. **Isolate, and let the offender crash.** Work is per connection or per item, in its own process, with a bounded cost. A peer that exceeds its bound loses its own process, not the node. In the gateway, `max_heap_size` with `include_shared_binaries` caps each connection process of the agent listener, whose peers are anonymous (finding N1, PR #5695). The bound is chosen for the peer it is meant to stop. The management listener's one peer is the pinned server, and by default its connection has no such cap: the cap also counts responses waiting to be written, so it killed the server's connection, and every call on it, when the agents of a fan-out answered together, before Cowboy's own output-buffer backpressure could act (N1, 2026-10-17 amendment in the threat model).
2. **Bound time as well as space.** Every wait has a deadline, including a request that never finishes arriving (N1). A deadline the gateway keeps for a caller fires a margin before the caller's own, so the caller gets an answer instead of having to cancel: thousands of cancels at once trip a flood guard (N2).
3. **Shed load at the edge, before the node fails.** At a memory high-water mark the gateway stops accepting new agent connections, and it resumes below the low-water mark (N1). The management plane is never shed.
4. **Backpressure through the protocol's own flow control.** The direction: inbound data is credited back as it is consumed, so the window bounds what a peer can queue. **The code does not do this yet.** The gateway's stream handler credits every DATA frame back as soon as it is received (`yuzu_grpc_stream_h`, `credit/1`), so the window does not slow a sender; the memory bounds of N1 cover the gap meanwhile. Crediting on consumption is #635.
5. **One message per intent across a hop.** A fleet-wide operation is one message to the component that owns its fan-out, and cancelling it is one signal to that owner, never N per-item messages (#5956). A flood guard tripped by our own trusted peer is a defect in how load is generated. It is not a reason to raise the guard.
6. **Flood guards stay finite, and are sized to the measured workload.** Example: the management listener's `max_received_frame_rate` is ten times Cowboy's default, because the server multiplexes a whole fan-out over one connection (PR #5695, B1).

## Consequences

- **The scale target is not yet evidenced.** The 2026-10-16 scale tests reached 25,000 agents per gateway, and the watchdog fired at 50,000. **Those runs used a scratch build that removed the registry's `pg:join` calls, which PR #5695 did not then contain; the PR as it stood stalled at about 15,000.** Removing those joins is now part of PR #5695, so the per-gateway figure has to be measured again on the PR's final head before it is relied on. The same runs measured about 360 KB per agent in plaintext and 490 KB with TLS, so 100,000 agents would need roughly 36 to 49 GB per gateway.
  - The biggest measured gains are independent of the transport: the registry's `pg:join` work, the held-notice cap, and batched dispatch over several channels (#5956).
  - The owner's current assessment is that Postgres on the server is the worst bottleneck at scale.
  - This ADR makes the target reachable by design. It does not claim the target is met.
- **Cowboy's defaults are now the gateway's defaults.** Every protective default has to be checked against a workload where the server multiplexes a fan-out over one connection (B1, N2 in the threat model).
- **The project now owns its gRPC framing, deadlines and status handling.** Those paths need their own tests and review. The real-wire CI gate in PR #5695 (a real server, gateway and agent, with the hop pinned over TLS) is part of that obligation.
- **Operators make one configuration move**, enforced by boot refusals: `servers` becomes `grpc_listeners`, and `client` becomes `upstream_client` (`docs/user-manual/upgrading.md`).
- **TLS 1.3 and session resumption remain open (#1293).** The layer is TLS 1.2 only.
