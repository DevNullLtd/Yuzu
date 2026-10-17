# Security review: the gateway's Cowboy/Ranch gRPC edge and gun upstream client

**Date:** 2026-10-16
**Subject:** The gateway's two listeners (agent `:50051`, management `:50063`) are served by a gRPC layer owned in this repository, running over Cowboy/Ranch. Its connection to the server (`GatewayUpstream`, `:50055`) is the gateway's own unary client over gun. grpcbox, chatterbox, hpack, acceptor_pool, gproc and the vendored, patched `gateway/_checkouts/grpcbox` are removed. The gateway now decides each agent's origin address itself, and `origin.sources` is a new configuration input that decides which peers are trusted.
**Base:** `feat/gateway-grpc-client` at `9f85b4253` (PR #5695). Statements about the code before the change are read at its merge base with `origin/dev`, `b5907d440`.
**Decision record:** ADR-0069 (`docs/adr/0069-gateway-transport-owned-grpc-cowboy-gun-overload-model.md`); history in ADR-0066's amendments of 2026-10-10 and 2026-10-11. Operator guide: `docs/user-manual/gateway.md` ("gRPC listeners", "Client addresses behind a proxy"). Upgrade steps: `docs/user-manual/upgrading.md`.
**Purpose of this record:** ADR-0066's 2026-10-10 amendment said this review was pending. It records the decision as far as the repository documents it, the trust surface the change adds, the invariants carried over from grpcbox and how the new layer enforces each one, and what remains open. It is a decision record, not a design proposal.

## Provenance and limits of this record

- **Review.** One read-only `security-guardian` pass by a model working from the authoring session's tooling. That is **not independent review**. Nothing was executed for this record: no eunit, wire suite, dialyzer or live rig was run. Wherever this record names a test file, the file exists, but its result was not observed for this record.
- **Citations.** Every citation is to `9f85b4253`, the head before the frame-rate fix in residual R1 (`ffbfc4c35`). Line numbers in `yuzu_grpc_listener.erl`, `sys.config.prod` and the user-manual pages have moved since.
- **Third-party code.** Cowboy 2.19.0, cowlib 2.21.0, Ranch 2.3.0 and gun 2.5.0 are pinned in `gateway/rebar.lock:3-11`. Statements about their behaviour come from reading the fetched package sources at those versions, not from tests.
- **A claim in this record that disagrees with the code is a defect in this record.**

## Scope: what is now owned code

The layer lives in `gateway/apps/yuzu_gw/src/`. Its module map is in `docs/erlang-gateway-build.md:29-41`.

| Concern | Before (grpcbox v0.17.1 + `YUZU_PATCH.md`, at `b5907d440`) | Now |
|---|---|---|
| HTTP/2 framing, HPACK, flow control, flood guards | chatterbox, hpack | Third-party: `cowboy_http2`/cowlib (server side), gun (client side). Not owned, but now the gateway's attack surface. |
| Acceptors | acceptor_pool | Ranch (`yuzu_grpc_listener.erl:321-335`) |
| Listener TLS options | `grpcbox_pool.erl` plus patch site 1 (configurable `verify`/`fail_if_no_peer_cert`) | Owned: `yuzu_grpc_listener:ssl_opts/1` (`:214-223`) |
| gRPC message framing and size ceiling | `grpcbox_frame` (no length ceiling, per the 2026 evidence comment on #635) | Owned: `yuzu_grpc_frame:decode/2` (`yuzu_grpc_frame.erl:45-57`) |
| Per-stream state machine, `auth_fun` order, data dropped after a status | `grpcbox_stream` plus patch site 2 (#1422 `trailers_sent` guard); the deadline path was not covered (#5591) | Owned: `yuzu_grpc_stream_h` (`:44-56`, `:111-150`, `:234-273`, `:384-405`) |
| Connection-pid accessor | Patch site 3 | Owned: `yuzu_grpc:conn_pid/1` (`yuzu_grpc.erl:63-69`) |
| Peer and origin attribution | Not exposed to handlers. The gateway's `peer_addr` came from `:authority`, else `x-forwarded-for` (`yuzu_gw_agent_service.erl:71`, `:358` at `b5907d440`) | Owned: `yuzu_grpc_origin` (pure); `yuzu_grpc:peer/1` and `origin/1` (`yuzu_grpc.erl:29-55`) |
| Route table, handler runner | grpcbox services | Owned: `yuzu_grpc_route`, `yuzu_grpc_runner` |
| Validation of the configuration shape | Largely none | Owned: closed key sets; legacy grpcbox keys are refused by name (`yuzu_grpc_listener.erl:120-134`, `:375-384`); a leftover `{grpcbox, servers\|client}` block refuses boot (`yuzu_gw_app.erl:858-897`) |
| Upstream client | grpcbox client over chatterbox | Owned: `yuzu_grpc_client`, `_channel`, `_config` over gun |

What this means for review: HTTP/2 parsing now has one implementation, Cowboy's, which is widely deployed. In exchange, every gRPC-level security property the vendored patches carried is now owned code in this repository, and Cowboy's defaults are now the gateway's defaults (see R1 and N2). The vendored-patch integrity gate (`verify-vendored-grpcbox.sh`) is gone. Its replacement is the hex package hashes in `rebar.lock` and the pin policy in `docs/dependency-updates.md:244-251` (cowboy and gun pinned to releases at least a month old).

## The decision

Recorded in the repository:

- **What.** The two listeners move to a thin gRPC layer over Cowboy/Ranch that the repository owns (ADR-0066, 2026-10-10 amendment). The upstream client moves to gun, and grpcbox leaves the gateway entirely (2026-10-11 amendment).
- **Who and when.** The project owner, on 2026-10-09 (ADR-0066 amendment, para. 2). PR 1 of 3 (`0c263a833`) is dated 2026-10-09 19:18 UTC. The listener cutover (`859f1acfe`) and its hardening (`7c3daa2d8`, 2026-10-10) follow, then the client swap (`6ae22d9e6`). No ADR number is assigned.
- **Alternatives that appear in the record.**
  - (a) Stay on grpcbox: work the fix backlog (#1172, #1293, #635, #3913, #5175) and take upgrades. This is the default path in ADR-0066's original Consequences bullet. ADR-0066's Context also records an October 2026 assessment that classified "nearly all" of about 50 open gateway issues as application-level or small grpcbox fixes.
  - (b) QUIC (msquic/quicer), which ADR-0066 itself withdraws.
  - (c) "Cowboy + gun", named only as an example of a separate decision that ADR-0066 did not adopt.
- **Facts in the record that bear on (a), but are not recorded as the reason.** The upstream fixes for the auth-reject and deadline late-DATA defects (tsloughter/grpcbox#122 and #123) were "not in v0.18.0, the latest release as of 2026-10-09" (`YUZU_PATCH.md` at `b5907d440`). Keeping grpcbox meant carrying three patch sites plus an integrity gate.

**Rationale (the owner, recorded 2026-10-16).** The "small grpcbox fixes" were small only if we kept making them ourselves:
- **No vendored fork.** Staying on grpcbox meant carrying a patched fork of a gRPC server indefinitely. The fixes the gateway depended on were not released upstream, and the maintainer did not respond. The owner does not want vendored code in the gateway.
- **Performance and tuning.** The gateway has known performance problems. Cowboy exposes the HTTP/2 machinery as tunable options, and it is the more modern and actively maintained stack.
- **Scale target.** Yuzu has to reach 1.2 million connected agents. The plan allows for up to about a thousand gateways, but **one gateway must support 100,000 agents**.
  - That needs backpressure, bounded mailboxes, let-it-crash isolation, load shedding and overload handling, built into the server, the agent and the gateway alike.
  - Cowboy's model of a process per connection with stream handlers, and its parallelism and concurrency, make that easier to build than a patched grpcbox.

Owning the thin gRPC layer also put the security-relevant paths under the project's control: the pin check before any handler exists, dropping data after a status, and peer and origin attribution.

**The scale target is not yet evidenced.** The 2026-10-16 scale tests reached 25,000 agents per gateway, and the watchdog fired at 50,000. Those runs used a scratch build that removed the registry's `pg:join` calls, which the PR did not then contain; the PR as it stood stalled at about 15,000 (corrected 2026-10-17; ADR-0069, Consequences). Removing the joins is now part of the PR, so the figure has to be measured again on its final head. They measured about 360 KB per agent in plaintext and 490 KB with TLS, so 100,000 agents is roughly 36 to 49 GB per gateway by arithmetic. The overload work this decision is meant to enable, including N1 below and #5956, is what has to close that gap. The transport choice alone does not.

**Other gRPC frameworks (the owner, recorded 2026-10-16).** No other gRPC framework was adopted. Each carried the same risk that removing grpcbox was meant to remove, or added a runtime:
- **grpcbox upstream master**, carrying #122/#123 unreleased: the same unresponsive-maintainer problem.
- **elixir-grpc**, Cowboy-based: it brings the Elixir runtime into an Erlang release.
- **Bluehouse `grpc`**, Erlang on Cowboy 2: dormant.

A thin layer owned in this repository over Cowboy and gun limits the dependency to the HTTP/2 libraries themselves, which are widely deployed and maintained.

grpcbox and chatterbox also could not be tuned to the target load. Cowboy and gun showed a clear path to stable behaviour under concurrency. The owner also notes that, on current evidence, Postgres on the server is the worst bottleneck at scale, not the gateway transport.

**The upstream client (the owner, recorded 2026-10-16).** The upstream client moved to gun for the same reasons as the listeners, and to remove grpcbox from the gateway completely.
- gun shares Cowboy's HTTP/2 implementation (cowlib) and its maintainers, so the gateway uses one HTTP/2 stack in both directions.
- The specific interest was gun's process per connection across a pool of connections (`yuzu_grpc_client_channel`). That is the model the Erlang community's established load-handling practice builds on: per-connection isolation, backpressure, bounded queues and load shedding. The project intends to apply that practice to the server hop.

**ADR (the owner, recorded 2026-10-16).** The decision has its own record: ADR-0069, `docs/adr/0069-gateway-transport-owned-grpc-cowboy-gun-overload-model.md`. That record also sets the overload model as binding direction. ADR-0066's amendments stay as history.

## Threat model: the `origin` modes and `origin.sources`

**The mechanism.** `yuzu_grpc_origin:resolve/4` is called once per stream from `yuzu_grpc_stream_h.erl:206-217`. It decides the origin by **who connected**, never by whether a claim matches the connection (`yuzu_grpc_origin.erl:8-9`, `:186-200`).

- `transport` (the default) returns the TCP peer and ignores every claim (`:188-189`).
- `proxy_protocol` and `forwarded_for` believe a claim only when the TCP peer is in `sources`. Otherwise the TCP peer is used and the stream is counted as `untrusted_source` (`:190-200`).
- When a trusted proxy sends no usable claim, the result is **no observation** (`undefined`), never the proxy's own address (`:202-213`, `:220-231`).
- `forwarded_for` reads only the entry `trusted_hops` places from the right. The entry is trimmed byte-wise, capped at 64 bytes and parsed with `inet:parse_strict_address` (`:215-288`). `trusted_hops` is limited to 0-31 (`:74`, `:109-111`).
- Validation refuses a proxy mode with no `sources`, refuses a `/0` network, and refuses an IPv4-mapped network with a prefix of 96 or less (`:98-160`).
- `forwarded_for` cannot be combined with an `auth_fun` (`yuzu_grpc_listener.erl:578-581`), and a management listener must use `transport` (`yuzu_gw_app.erl:1243-1244`).
- The address is never logged and never used as a metric label (`yuzu_grpc_origin.erl:44-48`, `yuzu_grpc_stream_h.erl:203-217`).

**The value is now set by the gateway.** `register_checked/2` overwrites `RegisterRequest.gateway_observed_peer` with the gateway's decision, or with empty when there is no observation, whatever the agent sent (`yuzu_gw_agent_service.erl:71-85`, `:144-149`). The gateway-internal `peer_addr` is the same decided value, or `<<"unknown">>`. Before this change it came from `:authority`, else `x-forwarded-for` (`yuzu_gw_agent_service.erl:71`, `:358` at `b5907d440`).

**What consumes it.**
- On the server, `ProxyRegister` normalises the value strictly (`server/core/src/peer_ip.hpp:159-176`). An empty value falls back to the gateway's transport IP with `origin_observed=false` (`gateway_service_impl.cpp:583-593`).
- The result becomes `source_ip` on the gateway-proxy enrollment **denial** and **success** audit rows (`:807`, `:872`).
- No authorization decision consumes it. The trusted-gateway-peer set (the #826 relaxation) is keyed on the gateway's transport IP (`:985`).
- `NotifyStreamStatus.peer_addr` carries the same value. A grep of `server/core/src` found no reader of it.
- **Consequence:** a forged origin falsifies audit attribution and can defeat a SIEM rule keyed on `source_ip` (the "race-loss IP must equal winner IP" detection named at `gateway_service_impl.cpp:577-578`). It does not grant access.

| Actor and position | What it can make the gateway record |
|---|---|
| A client of a `transport` listener | Nothing. Its TCP peer is recorded. Behind a proxy the operator has not configured, every agent is recorded as the proxy, and nothing flags it (`gateway.md:1746`). |
| A client that is not in `sources`, connecting directly to a proxied listener | Nothing. Its TCP peer is recorded and `untrusted_source` is counted. A `proxy_protocol` listener also closes a connection that sends no PROXY header within 1 s (Cowboy `cowboy_tls.erl:56-57`). |
| A client behind a trusted `proxy_protocol` proxy | Nothing. The proxy writes the header; Cowboy reads one header before TLS. |
| A client behind a trusted `forwarded_for` proxy | Any address, **if** `trusted_hops` is larger than the number of proxies that append to the header, or if the proxy passes the client's header through unmodified. The client controls everything to the left of the proxy's own entry (`yuzu_grpc_origin.erl:17-25`). |
| **Any host inside `sources`**, whether or not it is the proxy | **Any address.** It connects directly and sends its own PROXY header or `x-forwarded-for`. |
| An attacker on the path between the proxy and the gateway | Can rewrite `x-forwarded-for`. Under `proxy_protocol` it must hold a `sources` address for a full TCP handshake. Network segmentation is out of scope here. |
| A gateway older than this change (version skew) | Forwards whatever the agent sent. The server cannot tell (`agent.proto:66-86`, `gateway.md:1776`). |

**Concrete misconfiguration.** Suppose `sources => [{{10,0,0,0}, 8}]` is set because the F5 is in 10/8, and agents also live in 10/8. Then any agent, or anyone on that network, can connect to `:50051`, assert any address, and have it written as `source_ip` on its enrollment audit rows.
- No counter moves: the note is `ok`.
- The gateway does not log the real TCP peer.
- The server's `detail` records only the gateway node's own IP (`gateway_ip`).
- So **the real source is recorded nowhere** in Yuzu. Only network-side logs can reconstruct it.
- Validation refuses `/0` but accepts `/1`. Keeping `sources` narrow is the operator's job, and the guide says so (`gateway.md:1789-1790`). The audit row also does not record which mode produced the address (`gateway.md:1771-1773`, "a separate, later change").

## Invariants carried over, and where the new layer enforces them

1. **No `auth_fun` on the agent listener.**
   - `check_auth_fun/1` refuses with `auth_fun_on_agent_listener` (`yuzu_grpc_listener.erl:433-442`).
   - The test is broad (`serves_agent/1`, `:444-454`): `agent_pb` in `service_protos`, or `AgentService` routed. It therefore also catches `management_pb`, which embeds `AgentService`.
   - It runs at boot through `check_grpc_listeners/0` (`yuzu_gw_app.erl:981-1010`, `:1071`) and again in listener `init/1` (`yuzu_grpc_listener.erl:253-265`).
   - Two related refusals: `auth_fun_without_tls` (`:487-493`) and `auth_fun_behind_terminating_proxy` (`:578-579`).
   - Tests: `yuzu_grpc_listener_tests.erl`, `yuzu_gw_app_tests.erl`.
2. **Management SPKI pin plus `serverAuth` EKU, per stream, before any handler exists.**
   - `yuzu_grpc_stream_h:start/3` runs `authenticate/2` first, ahead of method lookup (`:111-136`).
   - `check_mgmt_peer/1` → `check_peer/2` compares the SHA-256 of the full SPKI DER (plain decode) against the pins and requires `id-kp-serverAuth` (`yuzu_gw_authz.erl:66-151`).
   - A refused stream ends in the `ended` phase, so every later DATA frame is dropped and no handler runs (`yuzu_grpc_stream_h.erl:268-273`, `:384-405`). This was patch site 2 of the vendored grpcbox. It is now native, and it also covers the deadline path (#5591).
   - The certificate is captured once per connection (`ssl:peercert`, Cowboy `cowboy_http2.erl:172-183`).
   - `reuse_sessions` is `false` (`yuzu_grpc_listener.erl:223`) and TLS 1.2 is the only version, so there are no session tickets. A resumed session therefore cannot restore an earlier peer's certificate on this hop, which side-steps the open question in `gateway-peer-authz-minimal-2026-10-07.md`.
   - **Unlike the server-side guard, there is no validity check per call.** Expiry is checked only in the handshake (see R8).
   - Tests: `yuzu_gw_authz_tests.erl`, `yuzu_gw_authz_rpc_tests.erl`, `yuzu_grpc_wire_tests.erl`.
3. **Fail closed when pins are empty or unusable.**
   - An empty pin set rejects with `no_pins_configured` (`yuzu_gw_authz.erl:76-80`).
   - Pins that all fail to resolve reject with `no_pins_resolved` (`:95-98`). A pin config that is not a list rejects with `bad_pin_config` (`:106-107`).
   - Any exception rejects with `internal_error` (`:67-72`). An `auth_fun` that raises, or returns anything except `true` or `{true, _}`, refuses the stream (`yuzu_grpc_stream_h.erl:125-136`).
4. **Management-plane posture boot guard (#1422).**
   - `check_mgmt_listener_posture/0` (`yuzu_gw_app.erl:1111-1137`) runs before the supervision tree starts, and the listeners are its last children (`:72-88`).
   - It identifies a management listener by `management_pb`, never by port (`:1172-1174`).
   - The defects it checks: plaintext; missing certificate material; `verify` other than `verify_peer`; `fail_if_no_peer_cert` other than `true`; an `auth_fun` that is not exactly `fun yuzu_gw_authz:check_mgmt_peer/1`; empty pins; a proxied origin (`:1220-1246`).
   - Exempt: a loopback bind, and only when `socket_opts` cannot move the bind (`:1176-1209`).
   - Refused whatever the escape hatch says: an improper listener list (`:1143-1155`).
   - Escape hatch: `allow_insecure_mgmt` set to the literal `true`, which boots with a warning (`:1115`, `:1118-1125`).
   - The guard checks that pins are present, not that they resolve. Item 3 is the runtime backstop for that.
   - Tests: `yuzu_gw_config_posture_tests.erl`, `yuzu_gw_app_tests.erl`.
5. **TLS shape.** Set by `ssl_opts/1` (`yuzu_grpc_listener.erl:214-223`):
   - versions `['tlsv1.2']` only, the same as stock grpcbox;
   - ECDHE AEAD suites chosen by the certificate's key type (`:109-118`, `:226-247`), where stock grpcbox set none and took the OTP defaults; an unreadable certificate gets the EC list (`:229`);
   - `honor_cipher_order` `true`, where stock grpcbox set `false` (`grpcbox_pool.erl:30` at `b5907d440`);
   - `reuse_sessions` `false`;
   - ALPN `h2`, where grpcbox used NPN; the layer serves HTTP/2 only (`:353-358`).

   A `ciphers` value set by the operator is used as given, checked only for shape (`:517-520`). The posture guard does not inspect it.
6. **Socket options may not move the bind.** `ip`, `ifaddr`, `fd`, `port` and `local` in `listen.socket_opts` are refused (`yuzu_grpc_listener.erl:153-155`, `:414-427`). The loopback test in the posture guard stays as a fail-safe.
7. **`max_message_bytes` refuses an oversized message before buffering it.** `decode/2` refuses a declared length above the limit as soon as the 5-byte header is seen, with `RESOURCE_EXHAUSTED` (`yuzu_grpc_frame.erl:41-52`). This applies both before a handler exists and while one runs (`yuzu_grpc_stream_h.erl:236`, `:284`). The default is 4 MiB (`yuzu_grpc.hrl`). It bounds **wire bytes per message**, not the decoded size and not the total across streams (see N1 and R3).
8. **Upstream TLS.** An `https` endpoint without `verify_peer` and a CA of its own refuses boot (`yuzu_gw_app.erl:811-852`). The SSL options are passed through unchanged (`yuzu_grpc_client_config.erl:13-16`).

## Residual risks and open items

- **R1. Cowboy's received-frame ceiling could close the single management connection. Fixed in this PR (`ffbfc4c35`).**
  - Cowboy's default `max_received_frame_rate` is `{10000, 10000}` (`cowboy_http2.erl:217`). Exceeding it closes the **whole** connection with `enhance_your_calm` (`:425-442`).
  - The server holds one connection per replica to `:50063` and fans every command out over it. At `9f85b4253` neither the listener defaults (`yuzu_grpc_listener.erl:339-342`) nor `sys.config.prod:230` override the ceiling.
  - `ffbfc4c35` gives any listener that routes `ManagementService` a default of `{100000, 10000}` (`yuzu_grpc_listener:http2_opts/1`) and sets it explicitly in `sys.config.prod` and the reference config. A real-listener test sends 6,000 calls over one connection; it loses 49 at the old value. The fix does not touch the cancel-rate guard (N2).
- **R2. The pin check stats the certificate file through the file server on every stream (#5696). Fixed in this PR (`467240cca`).** `yuzu_gw_mgmt_pins` now re-checks pin files in the background with `raw` file operations; the per-stream check is a memory read. What follows describes the code at `9f85b4253`.
  - With a `cert_file` pin, which is the shipped default (`sys.config.prod:84`), every stream calls `file:read_file_info/2` without `raw`, through the node-wide file server, inside the Cowboy connection process (`yuzu_gw_authz.erl:86`, `:188-205`, `:220-225`).
  - Any holder of an install-CA certificate that can reach `:50063` can drive it.
  - *Behaviour of the fix, as amended after review (2026-10-17).* (a) **Rotation window.** Between the server replacing its leaf and the watcher's next tick (at most `mgmt_pin_refresh_ms`, default 5 s) the gateway refuses the new leaf (`pin_mismatch`, fail closed). The server does not retry an UNAUTHENTICATED answer (`server.cpp`, the `gateway_unauthenticated` branch of the gateway forward): the commands forwarded in that window fail terminally. An earlier version of this record and of the code comments said the server's retry succeeded; that was wrong. Whether rotation should be seamless (pre-staged overlap pins, or a server-side retry) is open with the owner. (b) **Last known good.** As first shipped, one failed stat or read of a pin file withdrew the pin, refusing every management stream while `/readyz` stayed green. Now a pin that has resolved is kept when a later stat, read or parse fails; the source is reported unhealthy (`yuzu_gw_cert_file_readable{role="mgmt_peer_pin"}` = 0, alert `YuzuGatewayMgmtPinUnresolved`). A file read successfully with a different key replaces the pin. Consequence for withdrawal: deleting the pinned file no longer withdraws the key; replacing the file, or removing the entry and restarting, does. A file never readable since start still pins nothing. (c) **Alerting.** `YuzuGatewayMgmtAuthRejected` no longer counts `pin_mismatch`; `YuzuGatewayMgmtPinMismatch` fires on it except within 4 minutes of the watcher publishing a different key (`yuzu_gw_mgmt_pin_rotated_timestamp_seconds`), so a rotation does not page and a persistent mismatch or a probe with another serverAuth certificate does. Residual: a `pin_mismatch` probe that falls inside those 4 minutes is counted but not alerted.
- **R3. Decoded size against wire size.**
  - `decode_request/2` runs `Pb:decode_msg/2` in the connection process, after the whole message is buffered (`yuzu_grpc_stream_h.erl:299-304`).
  - How much larger the decoded term can be than the wire bytes was not measured. While a decode runs it holds up every other stream on that connection.
  - `gateway.md:1030` documents the per-stream bound only.
- **R4. Connection ceilings on the unauthenticated ports.** Documented in `gateway.md:1032-1072`.
  - Management port: an accepted limitation that will not be fixed in the gateway (owner decision, 2026-10-10). The port must be firewalled so only the server replicas reach it.
  - Agent port: an accepted residual. Connections are held open by `PING`; mitigate with a per-source limit at layer 4.
  - Neither covers memory per connection (N1).
- **R5. #635 (inbound stream data) is half closed.**
  - The size half is closed by item 7.
  - The rate half is open: every DATA frame is credited back on receipt, before the handler consumes it (`yuzu_grpc_stream_h.erl:254-264`, `:278-279`). This is deliberate (commit `0c263a833`: "Cowboy 2.19 only reopens a window for a stream that asked for flow").
  - `stream_loop/3` still forwards to the agent process with no check (`yuzu_gw_agent_service.erl:313-315`).
  - The limit is reached only by an agent that has completed registration.
- **R6. #1293 (TLS 1.3 and session resumption) remains open.** The layer is TLS 1.2 only.
- **R7. Origin.**
  - Wide `sources` are accepted down to `/1`.
  - The audit row does not record the mode.
  - Version skew passes a forged value through.
  - A claim accepted from a trusted source leaves no record of the real TCP peer.
  - All four are described in the threat model above.
- **R8. No per-stream validity check on the management peer.** A server leaf that expires on an open management connection is still admitted until the connection redials. This is parity with grpcbox and is not raised as a finding. The C++ server's guard does re-check validity on every call.
- **R9. #5591's keepalive criterion is open.** The late-DATA half is closed by the `ended` phase (`yuzu_grpc_stream_h.erl:271-273`).
- **R10. #3913 and #5175 are still OPEN in the tracker.** Their grpcbox code paths no longer exist. Disposition them as superseded; this was not verified behaviourally here.
- **R11. #1172 is still OPEN.** ADR-0066's 2026-10-10 amendment says its row is "done by that change". The issue should close on merge.

## New findings for triage

Each finding below states its trigger, impact, exposure and epistemic status, and the band derived from them. Each also gives the code path.

**N1. Unauthenticated peers can make the agent listener hold request memory in bulk. Fixed in this PR (`b69bcf177`).** The flood was reproduced first: about 110 MiB held per connection, linear in connections. Three bounds now apply. `max_heap_size` with `include_shared_binaries` caps each connection process at 16 MiB by default and kills only that connection. A request that never finishes arriving is aborted after 30 s. The agent listener is suspended above a node memory high-water mark. Each bound has a test. What follows is the finding as raised.
- *Trigger.* A peer with layer-4 reach to `:50051` completes one-way TLS; no certificate is needed (`sys.config.prod:143`). It then:
  - opens up to `max_concurrent_streams` (32, `sys.config.prod:146`) unary streams to a routed method such as `Register`;
  - on each one, sends a length prefix of 4194304 or less followed by all but the last body byte;
  - sends no `grpc-timeout`, so no deadline is armed (`yuzu_grpc_stream_h.erl:219-220`);
  - keeps the connection alive with `PING`, which resets the idle timer (`gateway.md:1044-1047`).
- *Code path.* Each stream holds up to `max_message_bytes` in `#st.buf`, and every DATA frame is credited back at once (`yuzu_grpc_stream_h.erl:234-250`, `:278-279`), so HTTP/2 flow control never slows the sender. That is about 128 MiB per connection, with up to 60000 connections (`sys.config.prod:172`).
- *Impact.* I5: memory exhaustion of the gateway node takes down the agent and management service on that node.
- *Exposure.* E1: unauthenticated, default shipped configuration.
- *Epistemic.* Likely: read from the code, not reproduced. The runtime's over-allocation on binary append was not measured.
- *Derived band.* **HIGH** (I5 base MEDIUM, raised one band by E1).
- *Not a demonstrated regression.* The comment on #635 records that stock grpcbox had no size ceiling at all.
- *Owner question.* Is this covered by the 2026-10-10 acceptance of connection holding, which is about file descriptors and slots, not memory?
- *Candidate fixes.* A receive deadline for a stream waiting for its request; a lower `max_concurrent_streams` on the agent listener; a buffered-bytes budget per connection or per node.

*Amendment, 2026-10-17: the ceiling is not applied to the management listener by default.* A review of the PR head found, and reproduced, that the per-connection ceiling also applied to the management listener (`:50063`), whose one peer is the pinned server sending a whole fan-out over one connection. The ceiling counts every refc binary the connection process references, so it counts the responses waiting to be written as well as half-finished requests. When the agents of a fan-out answer together with large responses, those responses arrive in the connection process faster than the server's flow-control window lets Cowboy write them. The derived 16 MiB equals Cowboy's own output-buffer alarm (`max_connection_buffer_size`, 16000000 bytes, at which Cowboy stops acknowledging the senders), and each stream holds one more response than the alarm counts, so the VM killed the connection, and every call on it, before the alarm could act. Raising the management listener's `max_concurrent_streams` to shorten a fan-out makes this more likely, since the ceiling did not scale with it.
- *Fix.* A listener that routes the `ManagementService` and does not serve the agent service now has no ceiling unless its `limits` set `max_connection_memory_bytes` (`yuzu_grpc_listener:stream_limits/1`). The agent listener keeps its ceiling, and so does a combined agent+management listener, which serves anonymous agents (it is a lab rig: the boot guard refuses it off loopback without `allow_insecure_mgmt`). The other two N1 bounds, the 30 s receive deadline and the node-level shedder, are unchanged; the management listener is still never shed.
- *Why the exemption is safe here.* Every stream on the management listener has passed the SPKI pin before any handler exists (the `auth_fun` runs first in `yuzu_grpc_stream_h`), so the flood N1 describes needs the server's own key. What one management connection can hold is then bounded by Cowboy's buffer alarm, about 16 MB, plus one response per stream in flight (at most `max_concurrent_streams` of them, each about the size of the agent's response, which the agent listener's `max_message_bytes` bounds). That worst case is large in theory (4096 x 4 MiB at the shipped management cap of 4096 streams) and was measured at about 1 GB for 5,000 answers of 256 KiB arriving inside 1 s; command responses are usually a few KB, and the server reads as fast as it can. The node-level shedder does not cover it (it suspends the agent listener only), so the stream cap is the bound, and it is why the cap stays at 4096 rather than higher (`docs/user-manual/gateway.md`, the `http2` row). An operator who wants a hard cap can set one explicitly.

*Amendment, 2026-10-17: three defects in the node-level shedder (the third N1 bound).* A review of the PR head (FortitudeEtc) found them; each now has a test that failed on the earlier code.
- *Refused, not queued.* The shedder suspends the agent listener with `ranch:suspend_listener/1`, which closes the listen socket, so a new agent connection is refused (`ECONNREFUSED`). The module comments and the manual said new connections wait in the kernel backlog; that was wrong. Refusing is kept as the behaviour and the text is corrected (`yuzu_gw_memory_shedder.erl` header, `docs/user-manual/gateway.md` "Node-wide memory load shedding"). The alternative, lowering Ranch's `max_connections` so the socket stays open, was rejected: a queued connection completes the TCP handshake, so the agent waits for a TLS answer until gRPC gives up (about 18 s) instead of backing off at once, a load balancer does not retry it on another node, the queued sockets hold kernel memory that a container's memory limit counts, and on resume the whole backlog is accepted at once. The test connects with `gen_tcp` while shed and asserts `{error, econnrefused}`, an established connection still answering and a new management connection still accepted (it passed on the earlier code too: the behaviour was already refusal).
- *A failed resume stranded the gateway.* Resuming opens the socket again and can fail (`eaddrinuse`, `emfile`). The shedder marked itself unshed whatever the result, so the listener stayed suspended for good, the gauge read 0 and `/readyz` stayed 503 with nothing retrying. A shedder that crashed while shed had the same effect: its restart began unshed and never resumed the listener. Now every tick reconciles each agent listener with the decision, a failed suspend or resume is retried on the next tick, logged (first failure, at most once a minute after, recovery), counted (`yuzu_gw_memory_shedding_transition_failures_total{action}`) and shown (`yuzu_gw_memory_shedding_transition_failing{action}`), and `YuzuGatewayMemorySheddingTransitionFailing` (critical) fires after 5 minutes of it. A restarted shedder adopts a listener it finds suspended. `/readyz` follows the listener's real state, so it is 503 while shed and while a resume is failing, and ready again only once the listener runs. Tests: a resume failing with `emfile` (meck on `ranch`), a real resume failing with `eaddrinuse` while another socket holds the port (in `yuzu_gw_health_tests`, through `/readyz`), a failing suspend, and a restart while shed.
- *Host memory, not the container limit.* The fractions were of `/proc/meminfo` `MemTotal`, so in a container with a memory limit below the host's memory the shedder never tripped before the OOM killer. The limit is now the smaller of host memory and the cgroup limit (v2 `memory.max`, v1 `memory.limit_in_bytes`, in the gateway's own cgroup and every parent), read once at start; an unreadable cgroup file is logged and skipped. The sampled number stays `erlang:memory(total)`, not `memory.current`, which counts reclaimable page cache; the 25% left above the default high-water mark covers what the VM's count leaves out (allocator overhead, kernel socket buffers). Tests use fixture files for v2, v2 on a parent cgroup, v1, both "unlimited" forms, an unparsable and an unreadable file, and no cgroup.
- *Test.* `yuzu_gw_mgmt_edge_tests:mgmt_burst_of_large_responses_test_/0`: 32 SendCommand streams on one connection to a listener with the shipped management limits, each releasing a 1 MiB response at the same moment. Before the fix every stream failed with the connection killed ("maximum heap size reached", 2097152 words); after it, every stream completes on the same connection. `connection_ceiling_by_listener_kind_test_/0` reads the ceiling each kind of listener sets.

**N2. Cowboy's cancel-rate guard can close the management connection under fan-out. Mitigated in this PR (2026-10-17) for expiring deadlines; the full fix stays with #5956.** The owner declined a stopgap that would raise the limit. The fix is to remove the source: one message per intent across the server→gateway hop, a gateway-side owner for each execution, and a single `CancelCommand` (ADR-0069, principle 5).

*The 2026-10-17 change (owner-approved as part of #5956's mechanism, without its batching).* The cancels come from the gateway's deadline and the client's coinciding: the stream handler armed the call's deadline at exactly the client's `grpc-timeout`, so the gateway's `DEADLINE_EXCEEDED` and the client's own deadline arrived together and the client reset every call still open. The gateway now ends a call with a `grpc-timeout` a margin before the client's deadline: a tenth of the timeout, at most 1 s (`yuzu_grpc_stream_h:deadline_ms/1`; 299 s for the server's 300 s). The margin has to cover the request's transit (the gateway's timer starts that much late), the time one connection process takes to write the statuses of thousands of streams expiring together, and their transit back; 1 s is far above all three on a LAN. A client that receives the status before its deadline has no stream to cancel. The router's own fan-out timer (`timeout_seconds`, 300 s) fires after the stream deadline, so the status the server sees for an unanswered call is `DEADLINE_EXCEEDED`, as it was when its own deadline fired.
- *Test.* `yuzu_gw_mgmt_edge_tests:mgmt_deadline_before_caller_test_/0`: 600 SendCommand streams on one connection share a 2 s client deadline, their handlers never answer, and the client resets what is still open at its deadline. Before: all 600 were still open, the client sent 600 resets, Cowboy closed the connection (`GOAWAY enhance_your_calm`) and a later call on it failed. After: every stream ends `DEADLINE_EXCEEDED` before the client's deadline, no resets are sent, and a later call succeeds on the same connection.
- *What is not verified.* The test client is gun, not the server's gRPC C++ client. That the C++ client sends no `RST_STREAM` for a call whose status arrived before its deadline is standard gRPC behaviour but was not observed against this server. A reset for any other reason (the server shutting down its calls, an operator cancel) still counts toward Cowboy's limit; that is #5956's single `CancelCommand`.
- *Log volume.* A reset that races a stream's own message used to make Cowboy log one `Received message ... for unknown stream` warning per stream, printing the whole message (for a handler's frame, the response body). The listeners now log these through `yuzu_grpc_cowboy_log`: at most one line per second per connection, the message's tag only.
- *Trigger.* More than 500 client `RST_STREAM`s inside 10 s on one replica's management connection.
  - Cowboy's default `max_cancel_stream_rate` is `{500, 10000}` (`cowboy_http2.erl:229`), enforced at `:710-724`.
  - The server sends one `SendCommand` per agent, each with a 300 s deadline (`server/core/src/server.cpp:13370-13411`), so a fan-out to more than 500 agents whose calls are still open when the deadline passes cancels them together (the territory of #5590).
  - That gRPC C++ cancels an expired call with `RST_STREAM` is general gRPC behaviour, not verified in this tree.
- *Impact.* I5: every call in flight on that connection fails. Its interaction with the server's 3-attempt retry (`server.cpp:13400-13405`) was not traced.
- *Exposure.* E0/E3: an ordinary fleet-wide command, default configuration.
- *Epistemic.* Likely for the Cowboy side; the client half is unverified.
- *Derived band.* **MEDIUM.**
- *Fix.* `max_cancel_stream_rate` is an allowed `http2` key (`yuzu_grpc_listener.erl:143`), so it can sit beside the R1 fix.

**N3. A stale comment. Fixed (`467240cca`).**
- *The comment.* `yuzu_gw_upstream.erl:653` says "The peer address is agent supplied".
- *The code.* Since this change the value is the origin the gateway decided (`yuzu_gw_agent_service.erl:79-85`).
- *Band.* I9, comment against code, derived **INFO**.

**N4. The management rejection log has no rate limit. Fixed (`467240cca`):** at most one line per reason per second, with a count of suppressed lines. The counter still counts every rejection.
- *Trigger.* A holder of any install-CA certificate (every enrolled agent) with reach to `:50063` opens streams repeatedly.
- *Code path.* `reject/1` writes one `notice` line per refused stream (`yuzu_gw_authz.erl:236-243`). The module doc presents per-certificate silence as an anti-spam measure (`:43-45`), but per-reason lines are unbounded. The runner's failure log, by contrast, is throttled (`yuzu_grpc_runner.erl`).
- *Impact.* I8: log volume.
- *Exposure.* E3; the port must be firewalled (R4).
- *Band.* Pre-existing behaviour; derived **LOW**.

## Where this is enforced

- **Routed-concern row:** the PKI row in `.claude/routed-concerns-access-control.md` (the management peer pin; never an `auth_fun` on `:50051`; the `yuzu_gw_app` boot guard).
- **Code:** the boot guards in `yuzu_gw_app.erl:72-88`.
- **Tests:** the eunit and wire suites named above, plus `yuzu_grpc_origin_tests.erl` and `yuzu_grpc_origin_wire_tests.erl` for attribution.

**Verdict, as raised (at `9f85b4253`):** NOT PASS. Two things blocked a merge: N1, and the decision rationale, which was not yet recorded.

**Verdict after the owner's review (2026-10-16): the blockers in this record are resolved.**
- **N1:** fixed and tested (`b69bcf177`).
- **The decision rationale:** recorded from the owner (see "The decision") and in ADR-0069.
- **N2:** open by the owner's decision (#5956). It is a defect in how load is generated, and its fix belongs to that design. On 2026-10-17 the expiring-deadline source was mitigated in this PR (the gateway answers a margin before the caller's deadline); other resets still count toward Cowboy's limit.
- **N1 amendment (2026-10-17):** the per-connection ceiling no longer applies to the management listener by default; tested.
- **N1 shedder amendment (2026-10-17):** the shedder refuses new agent connections (now documented as such), retries a failed suspend or resume and alerts when that lasts, and takes its fractions of the cgroup memory limit; tested.

The invariants carried over from grpcbox hold as read. This record is still the authoring session's own review and **not** independent. The PR's Gate 8 pass by non-author models is the independent check.
