# Evidence record - gateway heartbeat admission bound to the session's connection

- **Date:** 2026-10-03
- **Change:** branch `feat/gateway-heartbeat-connection-binding` (issue #3869; related to #1197, which this change does not fix)
- **Component:** Erlang gateway (`gateway/apps/yuzu_gw`), agent-facing `Heartbeat` handler
- **Reviewed by:** `/governance` gates 2 and 3 (security-guardian, docs-writer, gateway-erlang, architect, sre, quality-engineer): all six passed, none blocking. Gates 4, 6 and 8 followed: no blocking findings except one documentation finding (the older-agent recovery claim, see "Agent compatibility" below), found in Gate 4 and fixed. The remaining findings were should-fix and nice-to-have items (classification of the change as breaking, evidence home, runbook gaps, test hardening) and were addressed in the fix rounds listed below.
- **Reading this record:** it summarises local rig runs and local review notes. Nothing here is a CI result. Every figure is as recorded in those notes; where a statement was inferred rather than observed it says so.

## Scope

The gateway now admits an agent `Heartbeat` only for a session the gateway node holds and only on the HTTP/2 connection that opened the session's `Subscribe` stream (a session that has registered but not yet subscribed is held to the connection that sent its `Register`). Any other heartbeat is answered `NOT_FOUND` (`unknown session`), counted, and not buffered or forwarded. The decision reads node-local state only. There is no wire or server change, and no agent change for the supported topologies. Behaviour and operating guidance: `docs/user-manual/gateway.md` "Heartbeat admission"; design note: `docs/adr/2002-high-availability-architecture.md` section 7c.

This record covers the gateway agent listener (`:50051`) path through the gateway only.

## Tested SHAs

| Label | Commit | What ran on it |
|---|---|---|
| Rig run 1 | `2e884bb9b` | real agents, plaintext, one rig |
| Rig run 2 and Windows run | `1c145d78a` | real agents, plaintext and TLS, one rig; one Windows agent |
| Code tip at the first Gate 8 | `255b63c40` | eunit, dialyzer, Common Test (see below) |
| Code tip after fix round 2 | `ab3986ec1` | eunit and dialyzer by the fix agents (not rig runs; see below) |
| Code commit of fix round 3 | `21125cc3b` | comment, HELP text and test changes only; not rig-run; its eunit and dialyzer results are not recorded in this record |
| This record written at | `21125cc3b` plus the documentation commits of fix round 3 | none |

`2e884bb9b` and `1c145d78a` differ only in tests and documentation, so the gateway source on both rig runs is the same. The later fix commits were **not** run on a rig and are covered by the eunit suite only. Round 1: `605f117d2` (the session index calls tolerate a missing table), `3431d20ea` (`/readyz` reports `sessions_index`) and `026830cd9` (the rejection-summary log state is created at boot). Round 2 code commits: `e139c5e86` (boot-wiring test and two source comments), `9ad473534` (mismatch counter HELP wording), `942fe5770` and `c2d040a66` (test changes) and `ab3986ec1` (comments). The round-3 code commit `21125cc3b` changes a source comment, the `yuzu_gw_heartbeat_rejected_total` HELP text and tests only. The boot path of the final tip has not been exercised on a rig.

## Real-agent runs

All runs used the C++ agent built from the branch unless stated, a debug build of the server and a release build of the gateway, on one Linux box. Gateway rejection counters are gateway-wide, not per agent.

| Run | Commit | Topology | Agents | Duration | Counter results |
|---|---|---|---|---|---|
| 1: baseline, restarts, soak (steps 1 to 6) | `2e884bb9b` | plaintext, direct | 1, then 4 | about 31 min soak plus earlier steps; 111 samples at 30 s over the whole run | `rejected_total` (all three reasons) and `session_mismatch_total` were 0 in every sample |
| 1: rejection check (step 7) | `2e884bb9b` | plaintext, direct | 4 held sessions | seconds | 3 heartbeats for a held session sent from a separate connection: `NOT_FOUND`, not queued, mismatch counter 0 to 3. 3 heartbeats for an unknown session: `NOT_FOUND`, not queued, `unknown_session` 0 to 3. Real agents were unaffected |
| 1: registry process killed (8a) | `2e884bb9b` | plaintext, direct | 4 (agents built from the branch tree, version 0.14.0, which carries the 0.13.0 recovery) | about 25 s to recover | `unknown_session` rose 3 to 7 (one per agent), `registry_unavailable` stayed 0, all 4 agents admitted again without a manual restart |
| 1: gateway kill and SIGTERM, one agent SIGTERM, server kill and SIGTERM (steps 3, 4, 8b, 8c, 8d) | `2e884bb9b` | plaintext, direct | 1 to 4 | minutes each | counters 0 after each restart. After a server-only restart the gateway kept admitting heartbeats and the server logged `unknown session` for them (the known #1197 state) |
| 1: released agents (step 9) | `2e884bb9b` | plaintext, direct | v0.13.0 and v0.14.0-rc6, plus 3 branch agents | 10 min 32 s | counters 0; neither released agent logged a heartbeat failure |
| 2A: non-default heartbeat intervals | `1c145d78a` | plaintext, direct | agents at 1 s, 2 s, 120 s, plus the 30 s agents | 6 min 24 s | counters 0 in all 13 samples; the server acknowledged every admitted batch in full |
| 2B: mid-scale | `1c145d78a` | plaintext, direct | 25 extra agents, 27 sessions in total | 8 min soak, then 10 agents killed and restarted at once | counters 0 throughout; the server acknowledged exactly 27 agents x 16 heartbeats |
| 2D: SIGTERM log comparison | `1c145d78a` and the base gateway `d1c86111b` | plaintext, direct | 1 | about 1 min each | the two error-level shutdown lines were identical on both gateways, so they are not caused by this change |
| 2E: back-off ladder | `1c145d78a` | plaintext, direct | 2 (one at 1 s heartbeat) | 12 min | the session index table was emptied every 500 ms. Agent cooldown ladder 2, 4, ... 256, then 300 s cap; `unknown_session` rose by one per agent cooldown cycle; after the perturbation stopped, agents recovered within the cooldown; one later single perturbation reset the ladder to 2 s |
| 2F: L4 TCP forwarder | `1c145d78a` | nginx `stream`, plaintext | 2 | 8 min 23 s | counters unchanged from baseline, no heartbeat failures, 2 client TCP connections (one per agent) |
| 2G: HTTP/2-terminating proxy | `1c145d78a` | nginx `grpc_pass`, plaintext | 2 | 8 min 03 s | every heartbeat rejected: mismatch counter 0 to 18 (19 when the agents stopped), none reached the server. Agents still enrolled and received commands, re-registered on the 2 to 300 s ladder, and the server's online count flickered between 2, 1 and 0. The topology fails loudly in the counter and the summary log, not silently |
| 2H: one-way TLS, with and without a client certificate | `1c145d78a` | gateway listener one-way TLS (`verify_none`, `fail_if_no_peer_cert => false`) | 2 (one with an auto-provisioned client certificate, one without) | soak 8 min 21 s plus restarts of gateway, agents and server | counters 0 throughout. The C++ agent connected without an ALPN error although the listener advertises `h2` through NPN only (observed outcome; the mechanism is inferred) |
| Windows agent | `1c145d78a` (agent code identical to `d1c86111b`) | plaintext, direct | 1 | about 25 min over 2 runs, 50 samples at 30 s | counters 0 in every sample; 29 acknowledged heartbeats in run 1 at about 30 s spacing, no failure lines; one TCP connection observed (so a single connection carried `Subscribe` and `Heartbeat`, partly inferred) |

Proxy configurations used in runs 2F and 2G (rig addresses replaced by a placeholder):

```nginx
# Run 2F: L4 forwarder
stream {
    server {
        listen <rig-address>:50071;
        proxy_pass 127.0.0.1:50061;
    }
}

# Run 2G: HTTP/2-terminating proxy
http {
    server {
        listen <rig-address>:50072 http2;
        location / {
            grpc_pass grpc://127.0.0.1:50061;
            grpc_read_timeout 3600s;
            grpc_send_timeout 3600s;
        }
    }
}
```

Image `nginx:stable-alpine` (nginx 1.30.5, built with `--with-stream`). The long timeouts keep nginx's own 60 s `grpc_read_timeout` from affecting the idle `Subscribe` stream.

## Automated results (from the review notes)

At the post-round-2 tip `ab3986ec1`, run by the fix agents (these are not rig runs):

- eunit: 401 of 401 passed, three runs from a fresh `_build/test`.
- dialyzer: clean.
At the first Gate 8 tip `255b63c40` (not re-run after it unless listed above):

- eunit: 399 of 399 passed, three runs from a fresh `_build/test`, no flake. Alphabetical and reverse-alphabetical `--module=` runs also pass.
- dialyzer: clean (23 files).
- Common Test: end-to-end suite 5 of 5; integration suite 16 passed, 1 failed, 2 skipped. The one failure (`upstream.upstream_register_error_handling`) also fails on the base commit `d1c86111b`.
- `verify-vendored-grpcbox`: OK.
- Admission cost, micro-benchmark: about 0.12 to 0.18 microseconds added per admitted heartbeat. Endurance 300 s, twice per tree: no growth attributable to the change. A branch-only churn run with unique sessions held the index at 10,000 rows.

## Mutation checks

- Gate 3 (quality-engineer): 34 mutants run; 18 of the 24 security-relevant mutants were killed. The survivors (compare order when the key is `undefined`, the fence asserted on the routing table instead of the agents row, `Subscribe` taking its key from the pending row, a replay adopt writing the index row, and missing storm and churn coverage) were fixed in the fix round with new tests, each re-proved to fail (RED) with a scratch mutant.
- Gate 8 re-run: 9 mutants, 6 killed. The three survivors, as they stand after fix round 2:
  - the pid-blind unindex is now killed by `non_owner_cleanup_keeps_session` (`c2d040a66`); a fix agent saw the test fail against the pid-blind mutant;
  - the boot wiring is now killed by `boot_creates_summary_state_before_listener_and_sup_test` (`e139c5e86`); a fix agent saw it fail when the init call was deleted and when it was moved after `yuzu_gw_sup:start_link`;
  - `index_session` catching every error class stays an equivalent mutant, because `ets:insert` raises only `badarg`.
- No test kills a mutant of the `compare_exchange` that decides which of several concurrent first rejections writes the summary line: the race window is too small to hit reliably. A miss would produce extra log lines only, not a wrong admission decision.

## Agent compatibility

The `NOT_FOUND` recovery (escalating cooldown, then a forced `Subscribe` cancel and re-register) is in agent v0.13.0 and newer. In v0.12.0 the heartbeat path only logs `Heartbeat failed`. This was checked in `agents/core/src/agent.cpp` at the `v0.12.0` and `v0.13.0` tags. An older agent therefore does not re-register by itself if its heartbeats are rejected, and stays rejected until it is restarted or upgraded. This matters only when its heartbeats are rejected, which happens in three cases: a topology that breaks the one-connection assumption, a gateway running without the session index, and a gateway registry process restart or crash while connections stay up (run 1, step 8a: the registry recreates its tables empty and every heartbeat for the agents it held is rejected until they re-register; a node failover that leaves the session not held by the surviving node is expected to behave the same, inferred, not tested). The 25 s recovery of step 8a was observed with agents built from the branch (0.14.0-rc6 or newer). The released agents tested in run 1 (v0.13.0 and v0.14.0-rc6) were not driven into a rejection, and v0.12.0 was not run.

## Not tested

- A multi-node gateway with a real agent (a two-node registry unit test exists).
- A listener that requires client certificates, with a real agent (a test-client mutual TLS leg exists; the shipped listener does not require client certificates).
- A multiplexing HTTP/2 proxy with upstream keepalive.
- Fleet-scale rejection or re-registration storms (largest real run: 27 agents).
- Windows service mode, and a macOS agent.
- A real agent across a `GOAWAY` (the drain behaviour was characterised with a test HTTP/2 client only).
- A real hot code load (the missing-table case is a unit test that deletes the table inside the registry).
- A rig boot of the final tip (see "Tested SHAs").
- Rollback to the previous gateway: derived from the change, not run.
- Agent v0.12.0 behaviour (read from source only).

## Caveats

- The rig reports behind this record are local files, not committed artifacts. This document is a summary of them.
- Gateway counters reset when the gateway restarts, so the interval between the last sample before a gateway kill and the kill is not covered by the counter samples of run 1.
- The test-client mutual TLS leg (`certless_refused` in `yuzu_gw_heartbeat_conn_rpc_tests`) was vacuous at `1c145d78a`: a read timeout counted as a refusal, so it could pass when the listener did not refuse a client without a certificate. `21125cc3b` strengthens it (a control connection with the certificate must complete the handshake, and the certificate-less attempt must end in a TLS alert or a closed socket). This record did not re-run it, and the only claim made is that a test-client mutual TLS leg exists.
- Run 2 and the Windows run shared one gateway, so counters cannot say which agent caused a rejection.
