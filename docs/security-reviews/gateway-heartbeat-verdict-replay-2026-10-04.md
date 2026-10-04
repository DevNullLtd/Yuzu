# Evidence record - gateway replays the sessions the heartbeat verdict names

- **Date:** 2026-10-04
- **Change:** branch `feat/1197-gateway-heartbeat-reconcile` (issue #1197; builds on the server-side verdict recorded in `changelog.d/1197-batch-heartbeat-unknown-sessions.changed.md`)
- **Component:** Erlang gateway (`gateway/apps/yuzu_gw`): `yuzu_gw_heartbeat_buffer`, `yuzu_gw_upstream`, `yuzu_gw_registry`, `yuzu_gw_telemetry`. No server, proto or agent change.
- **Reviewed by:** `/governance` (security, SRE, architecture and gateway, documentation, consistency, enterprise-readiness, compliance and quality-engineering roles). Outcome in plain words: no blocking findings except one documentation finding (the replay of a session the server already knows is not free, and the docs did not say so), which the documentation fix round of this change addressed. The other findings were should-fix and nice-to-have items (circuit breaker interplay, runbook gaps, wording, tracking numbers) and were fixed in that round or recorded as follow-ups below.
- **Reading this record:** it summarises local rig runs and local review notes. Nothing here is a CI result. Every figure is as recorded in those notes; where a statement was inferred from the code rather than observed it says so.

## Scope

After a server-only restart the server answers every `BatchHeartbeat` with the session ids it does not hold. The gateway now validates that list, resolves the ids against the sessions it still holds, and replays exactly those through the existing registration-replay drip: one pending entry per agent, a per-session guard window, a cap on verdict appends, and the circuit breaker in front of every replay `ProxyRegister`. Behaviour and operating guidance: `docs/user-manual/gateway.md` "What happens when the server restarts"; design note: `docs/adr/2002-high-availability-architecture.md` section 7c, update 2026-10-04.

This record covers one core replica. No multi-replica run exists; the multi-replica statement is read from the code.

## Tested SHAs

| Label | Commit | What ran on it |
|---|---|---|
| Rig runs and automated results | `caef11df5` | real agent runs R1, R2, R2d, R2c, R5 and R6 (plaintext and TLS rigs, one box), plus eunit, dialyzer and Common Test (see below) |
| Documentation commits after the rig | the docs commits on top of `caef11df5` | documentation only; not rig-run |
| Later code-agent commits | test, comment and `format_status` changes after `caef11df5` | not rig-run; eunit and dialyzer only, see the PR for the final count |

The gateway source on the rig runs is the source at `caef11df5`. The commits after it change tests, comments, the crash-report `format_status` and documentation only (no replay decision logic), and were not run on a rig.

## Real-agent runs

All runs used one real agent, one core replica, debug builds and gateway log level debug, on one Linux box. T0 is the moment the restarted server's `/health` first returned 200. The labels follow the local rig notes; the numbers are the ones stated in `docs/user-manual/gateway.md` "Observed on a rig".

| Run | Scenario | Result |
|---|---|---|
| R1 | server killed for about 10 s, then restarted (plaintext) | gateway logged the INFO verdict line (`queued 1, not local 0, already queued 0, within guard 0, queue full 0`) and then `re-proxied`; server logged the adopt and `ProxyRegister succeeded` with the pre-restart session id. Replay at T0 + 17.5 s, on the first agent heartbeat after T0. `agents.online` back to 1; a read-only single-target command returned a result within 1 s of that. Same session id, same agent process, no reconnect. Over the next 71 s every counter stayed unchanged. Baseline (dev without this change, separate run): `agents.online` stayed 0 for about 280 s and the gateway never replayed |
| R2 | server down 300 s, route row expired before the restart | same session id and process recovered, lease advanced; the `renew_leases` `unknown_session` count stopped rising at 3; `route_reap_total{outcome="ok"}` went 0 to 1 at T0 + 300 s. The renew adopt path is INFERRED from the row state |
| R2d | recovery after that outage, breaker open at T0 | recovery took 58 s: breaker backoff had grown to 80 s, the first two verdicts were dropped (`verdict_dropped{reason="circuit_open"}` at 2), the breaker went half open at T0 + 54 s and the replay was the probe that closed it. A repeat run with the breaker never opened replayed at T0 + 4.2 s |
| R2c | route row tombstoned, then server killed for 10 s | replay at T0 + 17.5 s with the same signals; the row was repopulated with the same session. The reclaim path is INFERRED (a renew would match zero rows) |
| R2b | 6.9 minute gateway-to-server partition, server stayed up (traffic through a TCP proxy) | the server's lease reaper tombstoned the route row; `agents.online` stayed 1 and commands kept working; after the partition healed there was no verdict, no replay and no `ProxyRegister`, the `renew_leases` shortfall warning repeated every 30 s, and the row was still tombstoned 4 minutes later. Not repaired by this change (a Known limit in the gateway manual). The recovery action was NOT tested |
| R5 | Guaranteed State `full_sync` push after recovery | before the restart the push returned 202 and the agent logged `Guardian: apply_rules ok (applied=1, failed=0, pending=0, full_sync=true, generation=2, total=1)`; after recovery the same push produced the identical line 13 ms later. The earlier symptom of a push never delivered after a bounce was not reproduced |
| R6 | the R1 scenario with the server's default certificates, gateway-to-server mutual TLS, a management listener on mutual TLS with the certificate pin, and agent-to-gateway one-way TLS (then mutual TLS after CSR enrollment) | replay at T0 + 17.1 s, same session, same process, no reconnect, counters unchanged after convergence. The web UI was served over plain HTTP; the web UI over HTTPS was not tested |

## Automated results

At the rig commit `caef11df5` (fix-agent and reviewer runs, not rig runs):

- eunit: 458 of 458 passed, three runs from a fresh `_build/test`. For the count after the later test commits, see the PR for the final count.
- dialyzer: exit code 0.
- Common Test: 52 cases.

## Mutation checks

- Author mutants, each shown to fail a test before the fix was put back: stamping a session into the guard at enqueue time instead of at send time failed 7 tests; removing the open-breaker guard on the verdict path failed 1; removing the per-agent dedupe failed 1.
- Governance quality-engineering mutants a to j: the survivors and their disposition are recorded in the governance ledger run for this branch (`governance.d/`), not restated here.

## Declined obligations from the server-side verdict's governance ledger

The server-side change recorded obligations for the gateway consumer (finding `F-prc-obligations`). Three were declined, each for one reason:

- **Replay only ids seen in at least two batches (the two-batch rule).** Declined: the replay already re-checks local liveness when an id is queued and again immediately before every send, a per-agent pending entry and the guard window bound repeats, and a second batch would only add up to one heartbeat interval of latency.
- **A "verdict ever seen" gauge for version skew.** Declined: skew is a no-op in both directions by design (an old server never sends the fields, an old gateway ignores them), and `yuzu_gw_registration_replay_total` shows whether replays are being sent.
- **The exclusion half of "suppress replays while the directory is unavailable and exclude them from breaker accounting".** Declined: a replay that the server answers with `UNAVAILABLE` must still count toward the circuit breaker; the suppression half is met by the open-breaker drop and the guard window.

## Not tested

- More than one agent, scale, the `queue_full` and `malformed` verdict reasons.
- HA or several core replicas (a multi-replica statement exists, read from the code).
- Notify pressure, and agents started with `--no-auto-update`.
- A double replay (a verdict replay followed by a full breaker-recovery replay), a verdict that arrives after a replay it predates, the registry-unavailable abort, an `accepted=false` answer, and a failing server feeding the breaker during a drip.
- The recovery action for R2b: restarting the gateway or the agent was not tried.
- Whether restarting only the gateway recovers agents stranded by an earlier server restart.
- The web UI over HTTPS (R6 served it over plain HTTP).
- Rollback to the previous gateway: derived from the change (no schema, no migration, no required configuration), not run.

## Caveats

- The raw rig logs and reports behind this record are local files only, not committed artifacts. This document is a summary of them.
- The R-labels follow the local rig notes and are not otherwise defined in the repository.
- Two follow-ups have no issue number yet and are listed here for the owner to file: the route row tombstoned while the server stays up, together with the breaker-recovery full replay that the verdict drip can swallow (see "Known limits" in the gateway manual); and the red test for the reannounce failure case that follows this change.
- Related tracked items: #5244 (idempotent adopt), #4632 (in-flight notification limit), #5278 (verdict follow-ups), #5313 (re-registration load measurement), #4629 (disconnect without a session-match guard), #4627 (reap-versus-replay race after a long outage).
