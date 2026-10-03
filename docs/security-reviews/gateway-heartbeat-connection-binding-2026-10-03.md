# Evidence record - gateway heartbeat admission bound to the session's connection

- **Date:** 2026-10-03
- **Change:** branch `feat/gateway-heartbeat-connection-binding` (issue #3869; related to #1197, which this change does not fix)
- **Component:** Erlang gateway (`gateway/apps/yuzu_gw`), agent-facing `Heartbeat` handler
- **Reviewed by:** `/governance` gates 2 and 3 (security-guardian, docs-writer, gateway-erlang, architect, sre, quality-engineer): all six passed, none blocking. Gates 4, 6 and 8 followed: no blocking findings except one documentation finding (the older-agent recovery claim, see "Agent compatibility" below), found in Gate 4 and fixed. The other findings were should-fix and nice-to-have items (classification of the change as breaking, evidence home, runbook gaps, test hardening). Every finding raised during review was fixed in the fix rounds listed below or rejected with a recorded reason, except three recorded follow-ups that stay open: (1) re-registration load at fleet scale for the unsupported topologies is unmeasured, and the gateway has no registration rate limit (follow-up issue to be filed); (2) no alert rule ships for `yuzu_gw_heartbeat_session_mismatch_total` (follow-up issue to be filed); (3) 20 older commits on the branch lack a `Refs` trailer (history is not rewritten; the PR body cites #3869 and #1197).
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
| Code commit of fix round 3 | `21125cc3b` | comment, HELP text and test changes only; not rig-run; fix-agent runs at this commit and again at `188f6d4f4` (docs only on top): eunit 401 of 401, three runs each from a fresh `_build/test`; dialyzer exit 0 with no warnings; the strengthened mutual TLS test also passed 30 of 30 under about 64 busy loops |
| Rig run 4 (final gateway code) | `1e9c9784d` | real agents, released and branch builds, plaintext only, one rig (see "Rig run 4") |
| Code commit of fix round 4 | `e3c9989b4` | test change only: the churn test now cleans up its 240 holder processes and waits for the racers before asserting (process leak measured at 228 per run before, 0 after); fix-agent runs: eunit 401 of 401, three runs from a fresh `_build/test`; dialyzer exit 0 |
| Code commit of fix round 5 | `b19e4d818` | HELP text of the two heartbeat counters only; eunit 401 of 401 (one run from a fresh `_build/test`) and dialyzer exit 0 at this commit; not rig-run |
| Code commit of fix round 7 | `61ca35a3d` | test change only: `handoff_gap_rejects_then_admits` pins the `take_pending` to `register_agent` gap (admitted in the pending window, rejected as `unknown_session` after `take_pending`, admitted again after `register_agent/7`); fix-agent runs: eunit 402 of 402 (three runs from a fresh `_build/test` with `YUZU_REQUIRE_TLS_TESTS=1` exported) and dialyzer exit 0; the test fails when `take_pending` stops consuming the row; not rig-run |
| CI change | `f420c2318` | the `linux` job of `ci.yml` sets `YUZU_REQUIRE_TLS_TESTS=1`; the Windows and macOS legs do not; not run in CI at the time of writing |
| Code commit after an external review | `5ad179881` | the pending-session TTL (`store_pending`, `lookup_pending_session` and the sweep) now uses monotonic time instead of the wall clock; `pending_within_ttl_admitted` added and two tests that fabricate pending timestamps updated; fix-agent runs: eunit 403 of 403 (three runs from a fresh `_build/test` with `YUZU_REQUIRE_TLS_TESTS=1` exported) and dialyzer exit 0; not rig-run |
| This record written at | `5ad179881` plus the documentation, CI and ledger commits of the final rounds | none |

`2e884bb9b` and `1c145d78a` differ only in tests and documentation, so the gateway source on both rig runs is the same. The later fix commits were **not** run on a rig and are covered by the eunit suite only. Round 1: `605f117d2` (the session index calls tolerate a missing table), `3431d20ea` (`/readyz` reports `sessions_index`) and `026830cd9` (the rejection-summary log state is created at boot). Round 2 code commits: `e139c5e86` (boot-wiring test and two source comments), `9ad473534` (mismatch counter HELP wording), `942fe5770` and `c2d040a66` (test changes) and `ab3986ec1` (comments). The round-3 code commit `21125cc3b` changes a source comment, the `yuzu_gw_heartbeat_rejected_total` HELP text and tests only. Rig run 4 then exercised the gateway source at `1e9c9784d` (the boot path included). The commits after `1e9c9784d` (`050703fcc`, `e3c9989b4`, `b19e4d818` and the documentation commits of fix round 5) change tests, documentation and HELP text only, and were **not** run on a rig.

## Real-agent runs

All runs used the C++ agent built from the branch unless stated, a debug build of the server and a release build of the gateway, on one Linux box. Gateway rejection counters are gateway-wide, not per agent.

| Run | Commit | Topology | Agents | Duration | Counter results |
|---|---|---|---|---|---|
| 1: baseline, restarts, soak (steps 1 to 6) | `2e884bb9b` | plaintext, direct | 1, then 4 | about 31 min soak plus earlier steps; 111 samples at 30 s over the whole run | `rejected_total` (all three reasons) and `session_mismatch_total` were 0 in every sample |
| 1: rejection check (step 7) | `2e884bb9b` | plaintext, direct | 4 held sessions | seconds | 3 heartbeats for a held session sent from a separate connection: `NOT_FOUND`, not queued, mismatch counter 0 to 3. 3 heartbeats for an unknown session: `NOT_FOUND`, not queued, `unknown_session` 0 to 3. Real agents were unaffected |
| 1: registry process killed (8a) | `2e884bb9b` | plaintext, direct | 4 (agents built from the branch tree, version 0.14.0, which includes the #2182 fix) | about 25 s to recover | `unknown_session` rose 3 to 7 (one per agent), `registry_unavailable` stayed 0, all 4 agents admitted again without a manual restart |
| 1: gateway kill and SIGTERM, one agent SIGTERM, server kill and SIGTERM (steps 3, 4, 8b, 8c, 8d) | `2e884bb9b` | plaintext, direct | 1 to 4 | minutes each | counters 0 after each restart. After a server-only restart the gateway kept admitting heartbeats and the server logged `unknown session` for them (the known #1197 state) |
| 1: released agents (step 9) | `2e884bb9b` | plaintext, direct | v0.13.0 and v0.14.0-rc6, plus 3 branch agents | 10 min 32 s | counters 0; neither released agent logged a heartbeat failure |
| 2A: non-default heartbeat intervals | `1c145d78a` | plaintext, direct | agents at 1 s, 2 s, 120 s, plus the 30 s agents | 6 min 24 s | counters 0 in all 13 samples; the server acknowledged every admitted batch in full |
| 2B: mid-scale | `1c145d78a` | plaintext, direct | 25 extra agents, 27 sessions in total | 8 min soak, then 10 agents killed and restarted at once | counters 0 throughout; the server acknowledged exactly 27 agents x 16 heartbeats |
| 2D: SIGTERM log comparison | `1c145d78a` and the base gateway `d1c86111b` | plaintext, direct | 1 | about 1 min each | the two error-level shutdown lines were identical on both gateways, so they are not caused by this change |
| 2E: back-off ladder | `1c145d78a` | plaintext, direct | 2 (one at 1 s heartbeat) | 12 min | the session index table was emptied every 500 ms. Agent cooldown ladder 2, 4, ... 256, then 300 s cap; `unknown_session` rose by one per agent cooldown cycle; after the perturbation stopped, agents recovered within the cooldown; one later single perturbation reset the ladder to 2 s |
| 2F: L4 TCP forwarder | `1c145d78a` | nginx `stream`, plaintext | 2 | 8 min 23 s | counters unchanged from baseline, no heartbeat failures, 2 client TCP connections (one per agent) |
| 2G: HTTP/2-terminating proxy | `1c145d78a` | nginx `grpc_pass`, plaintext | 2 | 8 min 03 s | every heartbeat rejected: mismatch counter 0 to 18 (19 when the agents stopped), none reached the server. Agents still enrolled and received commands, re-registered on the 2 to 300 s ladder, and the server's online count flickered between 2, 1 and 0. The topology fails loudly in the counter and the summary log, not silently |
| 2H: one-way TLS, with and without a client certificate | `1c145d78a` | gateway listener one-way TLS (`verify_none`, `fail_if_no_peer_cert => false`) | 2 (one with an auto-provisioned client certificate, one without) | soak 8 min 21 s plus restarts of gateway, agents and server | counters 0 throughout. The C++ agent connected without an ALPN error although the listener advertises `h2` through NPN only (observed outcome; the mechanism is inferred) |
| Windows agent | `1c145d78a` (agent code identical to `d1c86111b`) | plaintext, direct | 1 | about 25 min over 2 runs, 50 samples at 30 s | counters 0 in every sample; 29 acknowledged heartbeats in run 1 at about 30 s spacing, no failure lines; one established TCP connection observed on the rig host (so a single connection carried `Subscribe` and `Heartbeat`, partly inferred). Source: a local Windows tester report |

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

## Rig run 4 (final gateway code)

Gateway source `1e9c9784d`, a release build; C++ agent built from the branch tree (version 0.14.0); released agents v0.13.0, v0.12.0 and v0.14.0-rc6 from their release packages (checksums verified against the release checksum files; signatures not verified). Plaintext only, one Linux box, one gateway node, 2026-10-03. The registry was killed with a distribution `exit(whereis(yuzu_gw_registry), kill)` call (the supervisor restarted it within the same second each time). Gateway counters are gateway-wide, not per agent. The full report is a local file and is not committed.

| Step | Result |
|---|---|
| Boot, before any agent | `/readyz` 200 with `sessions_index` true. Both counter families present at 0 (all three `reason` series and the `security` series). The boot info line `Heartbeat admission is connection-bound: ...` was logged. The only boot warning was the plaintext upstream |
| Same-connection admission | Branch agent, default 30 s heartbeat, 6 min 23 s: 12 heartbeats acked, all rejection counters 0, no `Heartbeat failed` line in the agent |
| Wrong-connection rejection | A heartbeat naming the agent's session, sent from a second connection: `NOT_FOUND` `unknown session`; `session_mismatch_total` 0 to 1, the three `rejected_total` reasons stayed 0; a trace of `yuzu_gw_heartbeat_buffer:queue_heartbeat/1` showed a call-count delta of 0 and the gateway upstream batch count did not change (nothing buffered or forwarded); the summary line reported `connection_mismatch=1`; the real agent kept being acked |
| Registry kill, branch agent | Four kills; each time one `unknown_session` rejection per attached agent (the rig recorded +1 per attached agent per kill), then `(#1894)` re-registration; recovery in 17 to 37 s (37, 37, 22 and 17 s on the four kills), acked heartbeats resumed |
| Registry kill, released v0.13.0, default settings | Rejected, logged `(#1894)`, then `Heartbeat thread stopped` and nothing more: no re-registration, no heartbeats, no connection to the gateway for 19 minutes, until the tester stopped it. Reproduced on a second fresh v0.13.0 (4 minutes). The same agent also did not notice a later gateway restart. v0.14.0-rc6 with default settings wedged the same way across the gateway restart (see below) |
| Registry kill, released agents with `--no-auto-update` | v0.13.0 re-registered 6 s after its rejection (20 s after the kill); v0.14.0-rc6 re-registered 7 s after its rejection (21 s after the kill) |
| Registry kill, released v0.12.0, default settings | `Heartbeat failed: unknown session` every 30 s, 29 failures in 14.5 minutes, never re-registered (one `Registered` line only). The gateway counted one `unknown_session` rejection per beat |
| Registry kill, released v0.12.0 with `--no-auto-update` | Watched for only about 2 minutes (from the kill at 10:01:02Z to about 10:02:56Z): it behaved the same way, with no re-registration in that window. No failure count was recorded for this run |
| Graceful gateway SIGTERM and restart | Branch agent: re-registered 11 s after the SIGTERM (12 s on a second SIGTERM), 0 rejections, acked heartbeats about 30 s later. Released agents with default settings (rc6, v0.13.0, v0.12.0) did not notice the lost `Subscribe` stream; their heartbeats got `NOT_FOUND` on the new gateway; rc6 and v0.13.0 logged `(#1894)` and then did not re-register within 1 min 40 s; v0.12.0 kept logging failures |
| Injected graceful `GOAWAY` | The tester wrote the frame (NO_ERROR) on the gateway-side HTTP/2 connection process of the branch agent; the gateway did not originate one. The next heartbeat went on a new connection: `session_mismatch_total` 0 to 1 (`rejected_total` unchanged), the agent logged `(#1894)` and re-registered 16 s after the `GOAWAY`, acked heartbeats resumed about 30 s later and stayed steady |
| Abrupt close of that agent's connection only | Re-registered in 9 s, no `(#1894)` line, counters unchanged |

**Released-agent finding.** The released v0.13.0 and v0.14.0-rc6 agents do not recover from a `NOT_FOUND` rejection with default settings, although the recovery logic is present in them (it worked with `--no-auto-update`). The cause is **inferred**, not traced: bug #2182 (the update-check thread join wedges the reconnect teardown), fixed by PR #5183, which is in the branch tree and, per `git tag --contains`, in no release tag. The control that supports the inference is the `--no-auto-update` result above. Agents older than 0.13.0 never recover by themselves (observed with v0.12.0; older than v0.12.0 is inferred from the agent source, not run). The user-facing documents were corrected accordingly: the recovery is described as present from v0.13.0 but dependent on the #2182 fix, with a restart as the interim action for an agent that stays rejected.

**Not tested in run 4:** TLS or mutual TLS, an HTTP/2-terminating or any other proxy, a multi-node gateway, scale, a `GOAWAY` that the gateway itself originates, and released agents on Windows or macOS.

## Automated results (from the review notes)

At the round-4 test commit `e3c9989b4` and the round-5 HELP commit `b19e4d818` (fix-agent runs, not rig runs): eunit 401 of 401 (three runs from a fresh `_build/test` at `e3c9989b4`, one at `b19e4d818`), dialyzer exit 0 at both. At the handoff-gap test commit `61ca35a3d`: eunit 402 of 402, three runs from a fresh `_build/test` with `YUZU_REQUIRE_TLS_TESTS=1` exported, dialyzer exit 0.

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
- Gate 8 re-run: 9 mutants, 6 killed. Of the three survivors, two were killed by tests added in fix round 2; status after that round:
  - the pid-blind unindex is now killed by `non_owner_cleanup_keeps_session` (`c2d040a66`); a fix agent saw the test fail against the pid-blind mutant;
  - the boot wiring is now killed by `boot_creates_summary_state_before_listener_and_sup_test` (`e139c5e86`); a fix agent saw it fail when the init call was deleted and when it was moved after `yuzu_gw_sup:start_link`;
  - `index_session` catching every error class stays an equivalent mutant, because `ets:insert` raises only `badarg`.
- No test kills a mutant of the `compare_exchange` that decides which of several concurrent first rejections writes the summary line: the race window is too small to hit reliably. A miss would produce extra log lines only, not a wrong admission decision.

## Agent compatibility

The `NOT_FOUND` recovery (escalating cooldown, then a forced `Subscribe` cancel and re-register) is in agent v0.13.0 and newer. In v0.12.0 the heartbeat path only logs `Heartbeat failed`. This was checked in `agents/core/src/agent.cpp` at the `v0.12.0` and `v0.13.0` tags. An older agent therefore does not re-register by itself if its heartbeats are rejected, and stays rejected until it is restarted or upgraded. This matters only when its heartbeats are rejected, which happens in four cases: a topology that breaks the one-connection assumption, a gateway running without the session index, a gateway registry process restart or crash while connections stay up (run 1, step 8a: the registry recreates its tables empty and every heartbeat for the agents it held is rejected until they re-register; a node failover that leaves the session not held by the surviving node is expected to behave the same, inferred, not tested), and, for released agents, a gateway process restart (rig run 4: the released agents tested did not notice the lost `Subscribe` stream and got `NOT_FOUND` on the new gateway, while the branch agent re-registered in 11 to 12 s with no rejections). The recovery of step 8a (about 25 s with four agents) and the 17 to 37 s over four registry kills in run 4 were observed with agents built from the branch tree (version 0.14.0, which includes the #2182 fix). The released agents tested in run 1 (v0.13.0 and v0.14.0-rc6) were not driven into a rejection there. Rig run 4 drove them (and v0.12.0) into one: the recovery logic from v0.13.0 is blocked in the released v0.13.0 and v0.14.0-rc6 with default settings (inferred cause: #2182, fixed by #5183, in no release yet) and worked with `--no-auto-update`; v0.12.0 never recovered (observed). The statement above that the recovery is "in agent v0.13.0 and newer" describes the source at the tags, not the behaviour of the released binaries.

## Not tested

- A multi-node gateway with a real agent (a two-node registry unit test exists).
- A listener that requires client certificates, with a real agent (a test-client mutual TLS leg exists; the shipped listener does not require client certificates).
- A multiplexing HTTP/2 proxy with upstream keepalive.
- Fleet-scale rejection or re-registration storms (largest real run: 27 agents).
- Windows service mode, and a macOS agent.
- A real agent across a `GOAWAY` that the gateway itself originates (run 4 injected the frame from the test side; the earlier drain characterisation used a test HTTP/2 client).
- A real hot code load (the missing-table case is a unit test that deletes the table inside the registry).
- TLS with the final gateway code (run 4 was plaintext only); the TLS runs are from `1c145d78a`.
- Rollback to the previous gateway: derived from the change, not run.
- Released agents on Windows or macOS, and a proxy, a multi-node gateway or scale in run 4.

## Caveats

- The rig reports behind this record, including the report for rig run 4, are local files, not committed artifacts. This document is a summary of them.
- Gateway counters reset when the gateway restarts, so the interval between the last sample before a gateway kill and the kill is not covered by the counter samples of run 1.
- The test-client mutual TLS leg (`certless_refused` in `yuzu_gw_heartbeat_conn_rpc_tests`) was vacuous at `1c145d78a`: a read timeout counted as a refusal, so it could pass when the listener did not refuse a client without a certificate. `21125cc3b` strengthens it (a control connection with the certificate must complete the handshake, and the certificate-less attempt must end in a TLS alert or a closed socket). This record did not re-run it, and the only claim made is that a test-client mutual TLS leg exists.
- Run 2 and the Windows run shared one gateway, so counters cannot say which agent caused a rejection.
