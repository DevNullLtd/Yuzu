# Evidence record - gateway replays the sessions the heartbeat verdict names

- **Date:** 2026-10-04
- **Change:** branch `feat/1197-gateway-heartbeat-reconcile` (issue #1197; builds on the server-side verdict recorded in `changelog.d/1197-batch-heartbeat-unknown-sessions.changed.md`)
- **Component:** Erlang gateway (`gateway/apps/yuzu_gw`): `yuzu_gw_heartbeat_buffer`, `yuzu_gw_upstream`, `yuzu_gw_registry`, `yuzu_gw_telemetry`. No server, proto or agent change.
- **Reviewed by:** `/governance` (security, SRE, architecture and gateway, documentation, consistency, enterprise-readiness, compliance and quality-engineering roles). Outcome in plain words: the first run found one derived-HIGH documentation finding (the side effects of replaying a session the server already knows). The re-review of the fix round found two further derived-HIGH items (upgrade-day guidance that omitted the wedge of released agents, and crash report redaction that covered the state but not the mailbox) and a number of MEDIUM and LOW items. All of them are addressed in this PR as documented here and in the Known limits of the gateway manual; the crash report mailbox residual was disclosed at that point, and a later round narrows it with a logger filter (see the later code commits and "Not tested" below).
- **Reading this record:** it summarises local rig runs and local review notes. Nothing here is a CI result. Every figure is as recorded in those notes; where a statement was inferred from the code rather than observed it says so.

## Scope

After a server-only restart the server answers every `BatchHeartbeat` with the session ids it does not hold. The gateway now validates that list, resolves the ids against the sessions it still holds, and replays exactly those through the existing registration-replay drip: one pending entry per agent, a per-session guard window, a cap on verdict appends, and the circuit breaker in front of every replay `ProxyRegister`. Behaviour and operating guidance: `docs/user-manual/gateway.md` "What happens when the server restarts"; design note: `docs/adr/2002-high-availability-architecture.md` section 7c, update 2026-10-04.

This record covers one core replica. No multi-replica run exists; the multi-replica statement is read from the code.

## Tested SHAs

| Label | Commit | What ran on it |
|---|---|---|
| Rig runs and automated results | `caef11df5` | real agent runs R1, R2, R2d, R2c, R5 and R6 (plaintext and TLS rigs, one box), plus eunit, dialyzer and Common Test (see below) |
| Documentation commits after the rig | the docs commits on top of `caef11df5` | documentation only; not rig-run |
| Later code commits | the code commits on top of `caef11df5` | input validation and log hardening, eunit and dialyzer only, NOT rig-run; listed below |

The gateway source on the rig runs is the source at `caef11df5`. The later code commits are not rig-run and are not limited to tests, comments and documentation. They add: the `consume_verdict` map guard and `listed_ids` in the heartbeat buffer; the cast-boundary cap and type check of `replay_sessions` (`bound_session_ids`, `replay_verdict`); control byte replacement in `reject_reason_for_log`; the HELP text correction of the truncated counter; and, in the second fix round, redaction of the reason and the log in `format_status`, an exception wrap of the RPC bodies, a non-map reply guard at the replay arm and in the agent service register, and C1 control byte replacement (the other logged server text, the gRPC message of a failed RPC, now goes through the same cut and replacement). A further round of post-rig code changes adds four more: `registration_replay_spacing_ms` is validated like the other two replay keys (default 20, valid 0 to 60000, otherwise the default with one warning naming the key); `heartbeat_batch_interval_ms` is validated (default 1000, valid 100 to 60000, otherwise the default with one warning naming the key) and the heartbeat buffer skips casting a verdict to the upstream client while that client's mailbox holds more than 100 messages, counting those ids as `yuzu_gw_heartbeat_verdict_dropped_total{reason="queue_full"}` with one debug line; the truncated-verdict warning is rate limited to one per 60 s per gateway node (the counter still counts every occurrence, and the warning text ends with `suppressed N`); and a logger primary filter, `yuzu_gw_crash_redact`, installed at application start, redacts the crash report and the supervisor `child_terminated` report of the upstream client (the process mailbox becomes a count, and the exception and reason keep no argument lists). Two behaviour changes come with them: an exception inside the upstream client's own RPC calls used to crash the process and reset the circuit breaker; it is now a counted failed RPC (telemetry code `exception`, one WARN with the exception class and a redacted reason); and a verdict is no longer cast while the upstream client's mailbox is over 100 messages, so the `queue_full` reason now covers a full replay queue or an upstream message backlog. They validate inputs and harden logging, and they were checked by eunit and dialyzer only.

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

At the rig-tested commit `caef11df5` (fix-agent and reviewer runs, not rig runs):

- eunit: 458 of 458 passed, three runs from a fresh `_build/test`.
- dialyzer: exit code 0.
- Common Test: 52 cases.

At the later code commits (not rig-run):

- eunit: 467 of 467 passed after the first governance fix round, and 473 of 473 after the second (three runs from a fresh `_build/test` each, no flake, no cancelled run). The count is for the branch before the merge of dev; the merge is re-run and reported on the PR.
- dialyzer: exit code 0 after the second fix round.
- Common Test: 52 cases passed after the second fix round.

For the code of the further round described above (the replay spacing and flush interval validation, the upstream mailbox check, the rate limited truncated warning and the crash report filter): see the PR for the final count at the branch tip. The figures above stay as dated history for the earlier rounds.

## Mutation checks

- Author mutants, each shown to fail a test before the fix was put back: stamping a session into the guard at enqueue time instead of at send time failed 7 tests; removing the open-breaker guard on the verdict path failed 1; removing the per-agent dedupe failed 1.
- Governance quality-engineering mutants a to j: the survivors and their disposition are recorded in the governance ledger fragment for this branch, `governance.d/1197-gateway-heartbeat-reconcile.*.jsonl` (it exists at merge), not restated here.

## Obligations from the server-side verdict's governance ledger

The server-side change recorded six obligations for the gateway consumer (finding `F-prc-obligations`, in `governance.d/1197-batch-heartbeat-unknown-sessions.1sz0KG.jsonl`). The ledger records only that they were linked to #1197 (disposition `linked-to-#1197`), with no rationale. The reasons below were RECONSTRUCTED from the code at the branch tip by the author of this change; they are not recovered from a stored decision. Status per obligation:

1. **Replay only ids seen in at least two batches (the two-batch rule).** Not adopted. Reason (reconstructed): the replay already re-checks local liveness when an id is queued and again immediately before every send, a per-agent pending entry and the guard window bound repeats, and a second batch would only add up to one heartbeat interval of latency.
2. **Check local liveness at replay time (no ghost resurrection).** Met by `yuzu_gw_registry:entries_for_sessions/1` at queue time, which requires the agent row to agree with the session index, and by `lookup_local_session/1` immediately before each send.
3. **Dedupe against the replay queue and reuse the drip pacing.** Met by one pending entry per agent (an already queued agent is skipped), the per-session guard window, and the verdict entries feeding the existing drip with its spacing.
4. **Suppress replays while the directory is unavailable and exclude them from breaker accounting.** Two halves. Suppression is approximated, not met: a verdict that arrives while the breaker is open is dropped, but an open breaker only approximates "the directory is unavailable", and a verdict that arrives half open is queued on purpose, because its first replay is the probe (`yuzu_gw_upstream.erl`, `replay_verdict` and `enqueue_sessions`). Excluding replays from breaker accounting is not adopted. Reason (reconstructed): a replay that the server answers with `UNAVAILABLE` must still count toward the circuit breaker, so a failing server can open it (see "Replay failures feed the shared circuit breaker" in the gateway manual).
5. **A "verdict ever seen" gauge for version skew.** Not adopted. Reason (reconstructed): skew is a no-op in both directions by design (an old server never sends the fields, an old gateway ignores them), and `yuzu_gw_registration_replay_triggered_total{trigger="heartbeat"}` and `yuzu_gw_registration_replay_total` show whether replays are being sent.
6. **Sanitise ids before logging in Erlang.** Met for the ids the server lists: the verdict path logs counts only, never ids. The pre-existing DEBUG line `Registration replay: re-proxied <agent> (adopted session <id>)` still logs the session id the server returned, unsanitised (INFERRED from the code; this change did not touch that line).

## Not tested

- More than one agent, scale, the `queue_full` and `malformed` verdict reasons on a rig (the mailbox backlog skip, the flush interval validation and the rate limited warning are covered by unit tests only).
- HA or several core replicas (a multi-replica statement exists, read from the code).
- Notify pressure, and agents started with `--no-auto-update`.
- A double replay (a verdict replay followed by a full breaker-recovery replay), a verdict that arrives after a replay it predates, the registry-unavailable abort, an `accepted=false` answer, and a failing server feeding the breaker during a drip.
- The recovery action for R2b: restarting the gateway or the agent was not tried.
- Whether restarting only the gateway recovers agents stranded by an earlier server restart.
- The web UI over HTTPS (R6 served it over plain HTTP).
- The crash report redaction of `yuzu_gw_upstream`. Covered, and tested on the real process in the unit suite: `format_status`, the caught RPC exceptions and the `yuzu_gw_crash_redact` logger filter (mailbox as a count, no argument lists in the exception and `messages:` lines of the crash report and the supervisor `child_terminated` report). Not rig-tested: no crash of the upstream client was provoked on a rig. Not covered: use of the module outside the application (no filter is installed there) and any report shape the filter does not recognise, and the earlier stand-in probe (OTP 28.4.2) result stays as the history of the first measurement (see "Known limits" in the gateway manual).
- Rollback to the previous gateway: derived from the change (no schema, no migration, no required configuration), not run.

## Caveats

- The raw rig logs and reports behind this record are local files only, not committed artifacts. This document is a summary of them.
- The R-labels follow the local rig notes and are not otherwise defined in the repository.
- Two follow-ups have no issue number yet and are listed here for the owner to file: the route row tombstoned while the server stays up, together with the breaker-recovery full replay that the verdict drip can swallow (see "Known limits" in the gateway manual); and the red test for the reannounce failure case that follows this change.
- Related tracked items: #5244 (idempotent adopt), #4632 (in-flight notification limit), #5278 (verdict follow-ups), #5313 (re-registration load measurement), #4629 (disconnect without a session-match guard), #4627 (reap-versus-replay race after a long outage).
